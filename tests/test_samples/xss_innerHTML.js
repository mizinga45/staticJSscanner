// Test: Cross-Site Scripting XSS (CWE-79)
// Expected: DETECTED at line 4
var userInput = location.search;
document.getElementById('output').innerHTML = userInput;
