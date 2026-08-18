use crate::core::platform::StringCallback;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// Manages serial port communication across platforms
/// Handles opening, closing, reading, writing, and automatic retries.
pub struct SerialManager {
    on_message: StringCallback,
    rx_buffer: String,
    port_name: String,
    baudrate: u32,
    port: Option<Box<dyn serialport::SerialPort>>,
    last_attempt: Instant,
    retry_delay: Duration,
}

impl SerialManager {
    pub fn new(on_message: StringCallback) -> Self {
        Self {
            on_message,
            rx_buffer: String::new(),
            port_name: String::new(),
            baudrate: 115200,
            port: None,
            last_attempt: Instant::now().checked_sub(Duration::from_secs(10)).unwrap(),
            retry_delay: Duration::from_millis(5000),
        }
    }

    pub fn open(&mut self, port_name: &str, baudrate: u32) -> bool {
        self.close();

        self.port_name = port_name.to_string();
        self.baudrate = baudrate;

        let port_result = serialport::new(&self.port_name, self.baudrate)
            .timeout(Duration::from_millis(5))
            .open();

        match port_result {
            Ok(mut p) => {
                let _ = p.clear(serialport::ClearBuffer::All);
                self.port = Some(p);
                true
            }
            Err(e) => {
                eprintln!("Error opening serial port {}: {}", self.port_name, e);
                false
            }
        }
    }

    pub fn close(&mut self) {
        self.port = None;
    }

    pub fn is_open(&self) -> bool {
        self.port.is_some()
    }

    pub fn write(&mut self, data: &str) -> bool {
        if let Some(port) = &mut self.port {
            match port.write_all(data.as_bytes()) {
                Ok(_) => true,
                Err(e) => {
                    eprintln!("Error writing to serial port {}: {}", self.port_name, e);
                    self.close();
                    false
                }
            }
        } else {
            false
        }
    }

    pub fn process_incoming_data(&mut self) {
        if let Some(port) = &mut self.port {
            let mut buffer = [0u8; 256]; 
            // Loop completely drains the buffer until it is empty or hits a timeout
            loop {
                match port.read(&mut buffer) {
                    Ok(0) => break,
                    Ok(t) => {
                        self.rx_buffer.push_str(&String::from_utf8_lossy(&buffer[..t]));
                    },
                    Err(_) => break, // Break the loop on WouldBlock/Timeout
                }
            }
        }

        while let Some(pos) = self.rx_buffer.find("\r\n") {
            let line = self.rx_buffer[..pos].to_string();

            if !line.is_empty() {
                (self.on_message)(&line);
            }

            self.rx_buffer.drain(..pos + 2);

            if self.rx_buffer.starts_with('\r') || self.rx_buffer.starts_with('\n') {
                self.rx_buffer.drain(..1);
            }
        }
    }

    pub fn try_reconnect(&mut self) -> bool {
        if self.is_open() {
            return true;
        }

        if self.last_attempt.elapsed() < self.retry_delay {
            self.last_attempt = Instant::now();
            println!("Attempting to reconnect to serial port {}...", self.port_name);

            if self.open(&self.port_name.clone(), self.baudrate) {
                println!("Serial port reconnected successfully.");
                return true;
            }
        }

        false
    }

    pub fn set_retry_delay(&mut self, delay_ms: u64) {
        self.retry_delay = Duration::from_millis(delay_ms);
    }
}