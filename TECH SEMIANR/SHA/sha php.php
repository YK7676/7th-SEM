<?php
  // login.php
  $username = $_POST['username'];
  $password = $_POST['password'];

  $salt = 'random_salt';
  $db_password = /* Retrieve the hashed password from the database using the given username*/;
  $hashed_password = hash('sha256', $password . $salt);
  
  if (hash_equals($db_password, $hashed_password)) {
    /* Login success */
  } else {
    /* Login failed */
  }
?>





One more code 

<?php
  // login.php
  $username = $_POST['username'];
  $password = $_POST['password'];

  $salt = 'random_salt';
  $iterations = 1000; // number of iterations for the PBKDF2 algorithm
  $key_length = 32; // length of the derived key in bytes

  $hashed_password = hash_pbkdf2('sha256', $password, $salt, $iterations, $key_length);

  $db_password = /* Retrieve the hashed password from the database using the given username*/;

  if (hash_equals($db_password, $hashed_password)) {
    /* Login success */
  } else {
    /* Login failed */
  }
?>
