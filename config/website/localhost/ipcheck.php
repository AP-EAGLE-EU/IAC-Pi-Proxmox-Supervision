<?php
header( 'Content-Type: text/plain' );
echo 'Server            : NGINX'. "\n";
echo 'Remote Address    : ' . $_SERVER['REMOTE_ADDR'] . "\n";
echo 'Server Address    : ' . $_SERVER['SERVER_ADDR'] . "\n";
echo 'Server Port       : ' . $_SERVER['SERVER_PORT'] . "\n\n";
?>