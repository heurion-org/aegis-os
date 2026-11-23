# VHS tape to record a real terminal MP4/GIF of the 10-second red-team demo.
# Install VHS: https://github.com/charmbracelet/vhs
# Run from repo root: vhs scripts/record_demo.tape

Output assets/demo-terminal.gif
Set Shell "bash"
Set FontSize 15
Set Width 1100
Set Height 640
Set Padding 20
Set Theme "Catppuccin Mocha"
Set TypingSpeed 35ms

Type "aegis-os audit-me"
Enter
Sleep 2.5s

Type "./examples/redteam-demo/run_demo.sh"
Enter
Sleep 6s
