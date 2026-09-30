function paint(raw) {
  document.getElementById("out").innerHTML = raw;
}

function loadRequested(req) {
  const fs = require("fs");
  return fs.readFileSync(req.query.file);
}

function acceptToken(token) {
  return jwt.decode(token);
}
