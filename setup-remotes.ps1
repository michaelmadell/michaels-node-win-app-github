# Run once after cloning to configure all remotes
git remote add Github https://github.com/michaelmadell/michaels-node-win-app-github.git
git remote add all git@bitbucket.org:ahkengteam/michaels-node-win-app.git
git remote set-url --add --push all git@bitbucket.org:ahkengteam/michaels-node-win-app.git
git remote set-url --add --push all https://github.com/michaelmadell/michaels-node-win-app-github.git
Write-Host "Remotes configured:"
git remote -v