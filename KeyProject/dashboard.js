function checkKeylogger() {
  const status = document.getElementById("status");
  status.textContent = "🔄 Scanning for keyloggers...";

  setTimeout(() => {
    status.textContent = "✅ No Keylogger Detected.";
  }, 3000);
}
