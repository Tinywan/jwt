<?php

require '../vendor/autoload.php';

// Your secret key (keep this secure)
$secretKey = 'Tinywan2024040000011';

// Create an instance of Jwt
$jwt = new \Tinywan\Jwt($secretKey);

// Create a JWT
$payload = [
    "user_id" => 2024,
    "username" => "Tinywan",
    "exp" => time() + 3600, // Token expiration time (1 hour)
];
$token = $jwt->createToken($payload);

echo 'JWT Token: ' . $token . PHP_EOL;

// Validate and decode the JWT
if ($jwt->validateToken($token)) {
    echo 'JWT is valid.' . PHP_EOL;
    $decodedPayload = $jwt->decodeToken($token);
    echo "Decoded Payload: " . json_encode($decodedPayload, JSON_PRETTY_PRINT).PHP_EOL;
    var_dump(json_decode(json_encode($decodedPayload), true));
} else {
    echo 'JWT is invalid.' . PHP_EOL;
}