use crate::core::platform::Platform;
use chrono::{DateTime, Duration as ChronoDuration, Local, NaiveDateTime, TimeZone};
use std::sync::{Arc, Condvar, Mutex};
use std::thread;
use std::time::Duration;

pub type SendFn = Box<dyn Fn(&str) + Send + Sync>;

const DEFAULT_GRACE_PERIOD: Duration = Duration::from_secs(15);

struct ScheduledActionState {
    action_pending: bool,
    cancel_requested: bool,
}

pub struct CmcCommandHandler {
    platform: Arc<Mutex<Box<dyn Platform>>>,
    send_to_mec: Arc<SendFn>,
    state: Arc<(Mutex<ScheduledActionState>, Condvar)>,
}

impl CmcCommandHandler {
    pub fn new(platform: Arc<Mutex<Box<dyn Platform>>>, send_to_mex: SendFn) -> Self {
        Self {
            platform,
            send_to_mec: Arc::new(send_to_mex),
            state: Arc::new((
                Mutex::new(ScheduledActionState {
                    action_pending: false,
                    cancel_requested: false,
                }),
                Condvar::new(),
            )),
        }
    }

    pub fn handle(&self, message: &str) {
        let tokens = split_tokens(message);

        if tokens.is_empty() || tokens[0].is_empty() {
            let p = self.platform.lock().unwrap();
            p.show_message_dialog("Command from CMC", message);
            return;
        }

        let verb = tokens[0].as_str();

        if verb.eq_ignore_ascii_case("ping") {
            (self.send_to_mec)("pong");
            return;
        }

        if verb.eq_ignore_ascii_case("status") {
            let p = self.platform.lock().unwrap();
            let response = format!(
                "status, cpu={}%, ram={}%, uptime={}",
                p.get_cpu_usage_percent(),
                p.get_ram_usage_percent(),
                p.get_system_uptime()
            );
            (self.send_to_mec)(&response);
            return;
        }

        if verb.eq_ignore_ascii_case("ct") {
            let current_time = format_local_time(Local::now());
            (self.send_to_mec)(&format!("ct, {}", current_time));
            return;
        }

        if verb.eq_ignore_ascii_case("shutdown") || verb.eq_ignore_ascii_case("restart") {
            if tokens.len() > 1 && tokens[1].eq_ignore_ascii_case("force") {
                let reason = join_from(&tokens, 2);
                self.begin_immediate_action(verb, &reason);
                return;
            } 

            if tokens.len() > 1 && tokens[1].eq_ignore_ascii_case("timeout") {
                if tokens.len() <= 2 || tokens[2].is_empty() {
                    (self.send_to_mec)(&format!("{} Rejected, timeout value missing", verb));
                    return;
                }

                if let Some(duration) = parse_duration_string(&tokens[2]) {
                    let deadline = Local::now() + duration;
                    let reason = join_from(&tokens, 3);
                    self.begin_scheduled_action(verb, deadline, &reason);
                } else {
                    let p = self.platform.lock().unwrap();
                    p.log_message(&format!("CMC {} rejected: invalid timeout '{}'", verb, tokens[2]));
                    (self.send_to_mec)(&format!("{} Rejected, invalid timeout '{}'", verb, tokens[2]));
                }
                return;
            }

            if tokens.len() > 1 && tokens[1].eq_ignore_ascii_case("time") {
                if tokens.len() <= 2 || tokens[2].is_empty() {
                    (self.send_to_mec)(&format!("{} Rejected, time value missing", verb));
                    return;
                }

                if let Some(deadline) = parse_duration_string(&tokens[2]) {
                    let reason = join_from(&tokens, 3);
                    self.begin_scheduled_action(verb, deadline, &reason);
                } else {
                    let p = self.platform.lock().unwrap();
                    p.log_message(&format!("CMC {} rejected: invalid time '{}'", verb, tokens[2]));
                    (self.send_to_mec)(&format!("{} Rejected, invalid time '{}'", verb, tokens[2]));
                }
                return;
            }

            let deadline = Local::now() + ChronoDuration::from_std(DEFAULT_GRACE_PERIOD).unwrap();
            let reason = join_from(&tokens, 1);
            self.begin_scheduled_action(verb, deadline, &reason);
            return;
        }

        if verb.eq_ignore_ascii_case("cancel") {
            self.cancel_pending();
            return;
        }

        if verb.eq_ignore_ascii_case("lock") {
            let p = self.platform.lock().unwrap();
            p.log_message("CMC Command: log off active session");
            (self.send_to_mec)("loggingOff");
            p.logoff_active_session();
            return;
        }

        let p = self.platform.lock().unwrap();
        p.show_message_dialog("Command from CMC", message);
    }

    fn begin_immediate_action(&self, verb: &str, reason: &str) {
        let p = self.platform.lock().unwrap();
        let reason_str = if reason.is_empty() { String::new() } else { format!(" Reason: {}", reason) };

        p.log_message(&format!("CMC Command: {} initiated.{}", verb, reason_str));
        (self.send_to_mec)(&format!("{} initiated.{}", verb, reason_str));

        invoke_action(&**p, verb, reason);
    }

    fn begin_scheduled_action(&self, verb: &str, deadline: DateTime<Local>, reason: &str) {
        let (lock, _) = &*self.state;
        let mut state = lock.lock().unwrap();

        state.action_pending = true;
        state.cancel_requested = false;

        let thread_state = Arc::clone(&self.state);
        let thread_platform = Arc::clone(&self.platform);
        let thread_send = Arc::clone(&self.send_to_mec);
        let verb_clone = verb.to_string();
        let reason_clone = reason.to_string();

        thread::spawn(move || {
            run_scheduled_action(
                thread_state,
                thread_platform,
                thread_send,
                verb_clone,
                deadline,
                reason_clone,
            );
        });
    }

    fn cancel_pending(&self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();

        if !state.action_pending {
            (self.send_to_mec)("No pending action to cancel.");
            return;
        }

        state.cancel_requested = true;
        cvar.notify_all();
    }
}

impl Drop for CmcCommandHandler {
    fn drop(&mut self) {
        let (lock, cvar) = &*self.state;
        let mut state = lock.lock().unwrap();
        state.cancel_requested = true;
        cvar.notify_all();
    }
}

fn run_scheduled_action(
    state: Arc<(Mutex<ScheduledActionState>, Condvar)>,
    platform: Arc<Mutex<Box<dyn Platform>>>,
    send_to_mec: Arc<SendFn>,
    verb: String,
    deadline: DateTime<Local>,
    reason: String,
) {
    let target_str = format_local_time(deadline);
    let reason_suffix = if reason.is_empty() { String::new() } else { format!(", {}", reason) };
    let reason_msg = if reason.is_empty() { String::new() } else { format!(" Reason: {}", reason) };

    {
        let p = platform.lock().unwrap();
        p.log_message(&format!("CMC {} scheduled for {}.{}", verb, target_str, reason_suffix));
        send_to_mec(&format!("{}Pending, {}{}", verb, target_str, reason_suffix));
        p.show_message_dialog(
            "Command from CMC",
            &format!("The Chassis Management Controller has requested a {} at {}.{}", verb, target_str, reason_msg),
        );
    }

    let (lock, cvar) = &*state;
    let mut state_guard = lock.lock().unwrap();

    let wait_duration = (deadline - Local::now()).to_std().unwrap_or(Duration::from_secs(0));

    let (mut state_guard, wait_result) = cvar.wait_timeout(state_guard, wait_duration).unwrap();

    let cancelled = state_guard.cancel_requested;
    state_guard.action_pending = false;

    drop(state_guard);

    let p = platform.lock().unwrap();
    if cancelled {
        p.log_message(&format!("CMC {} cancelled before execution.", verb));
        send_to_mec(&format!("{}Cancelled", verb));
        return;
    }

    p.log_message(&format!("CMC {} scheduled time reached; executing.", verb));
    send_to_mec(&format!("{}Executing", verb));
    invoke_action(&**p, &verb, &reason);
}

fn invoke_action(platform: &dyn Platform, verb: &str, reason: &str) {
    let reason_opt = if reason.is_empty() { None } else { Some(reason) };

    if verb.eq_ignore_ascii_case("shutdown") {
        platform.shutdown_system(reason_opt);
    } else if verb.eq_ignore_ascii_case("restart") {
        platform.restart_system(reason_opt);
    }
}

fn split_tokens(message: &str) -> Vec<String> {
    message.split(',').map(|s| s.trim().to_string()).collect()
}

fn join_from(tokens: &[String], idx: usize) -> String {
    if tokens.len() <= idx {
        return String::new();
    }
    tokens[idx..].join(", ")
}

fn parse_duration_string(s: &str) -> Option<ChronoDuration> {
    if s.len() < 2 { return None; }

    let (digits, unit) = s.split_at(s.len() - 1);
    let value: i64 = digits.parse().ok()?;

    if value <= 0 { return None; }

    match unit.to_lowercase().as_str() {
        "s" => Some(ChronoDuration::seconds(value)),
        "m" => Some(ChronoDuration::minutes(value)),
        "h" => Some(ChronoDuration::hours(value)),
        _ => None,
    }
}

fn parse_local_datetime(s: &str) -> Option<DateTime<Local>> {
    let naive = NaiveDateTime::parse_from_str(s, "%Y-%m-%d %H:%M:%S").ok()?;
    Local.from_local_datetime(&naive).single()
}

fn format_local_time(dt: DateTime<Local>) -> String {
    dt.format("%Y-%m-%d %H:%M:%S").to_string()
}