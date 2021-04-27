# On Your Own

In the Starting Point machine Oopsie, we left it after having discovering an image upload page that does not validate the file being uploaded. We also knew where the file was likely to be uploaded to as we had discovered an /uploads directory. Using the PHP reverse shell php-reverse-shell.php in the /usr/share/webshells/php directory, upload the file after editing it with your listener's details, start a Netcat listener and get a reverse shell. Upgrade the shell to a full TTY. Explore the /var/www/html/cdn-cgi/login directory to find the credentials for 'robert'. Use those credentials to become that user by using 'su robert'.

