// script.js
document.getElementById("login-form").addEventListener("submit", function(event) {
  event.preventDefault();

  var password = document.getElementById("password").value;
  var salt = 'random_salt';
  var hash = CryptoJS.SHA256(password + salt).toString();
  document.getElementById("password").value = hash;

  this.submit();
});
