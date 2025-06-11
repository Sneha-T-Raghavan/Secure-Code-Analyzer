const API_KEY = "12345-abcde-67890-fghij"; // Hard-coded API key

function executeUserCode(code) {
    // Dangerous: executes arbitrary code
    eval(code);
}

console.log("API Key:", API_KEY);
executeUserCode("console.log('User code executed')");