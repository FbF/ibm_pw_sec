<?php
/**
 * PHP IBM PartnerWorld Session Exchange Library
 *
 * @author Neil Crookes
 * @copyright Neil Crookes
 * @package IbmPwSec
 * @license http://www.opensource.org/licenses/mit-license.php The MIT License
 */

/**
 * Example session receiver script to illustrate usage of the PHP IBM
 * PartnerWorld Session Exchange Library.
 *
 * The first time you run this script you should see the decrypted XML message
 * string containing the user details. The second time however, an Exception
 * will be thrown, if running within 3 minutes of the first time because a
 * duplicate signature will have been detected.
 */

// Initialise certificate variable, this can be read from a file or hard coded
// in your session receiver script, or included etc. See the IbmPwSec class
// constructor for more information about acceptable forms of this parameter.
$certificate = '-----BEGIN CERTIFICATE-----
MIICVzCCAcCgAwIBAgIES1H+7TANBgkqhkiG9w0BAQQFADBwMQswCQYDVQQGEwJVUzE0MDIGA1UE
ChMrSW50ZXJuYXRpb25hbCBCdXNpbmVzcyBNYWNoaW5lcyBDb3Jwb3JhdGlvbjEVMBMGA1UECxMM
UGFydG5lcldvcmxkMRQwEgYDVQQDEwt3d3cuaWJtLmNvbTAeFw0xMDAxMTYxODAxMTdaFw0xNTAx
MTUxODAxMTdaMHAxCzAJBgNVBAYTAlVTMTQwMgYDVQQKEytJbnRlcm5hdGlvbmFsIEJ1c2luZXNz
IE1hY2hpbmVzIENvcnBvcmF0aW9uMRUwEwYDVQQLEwxQYXJ0bmVyV29ybGQxFDASBgNVBAMTC3d3
dy5pYm0uY29tMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC86ktmxPFVnV5fUVYE2y3joYdn
3wo6M+fsWxOJKyAnXqgQ2aCP7dZON97SAyaYucCHxJ4Gld9T/K0bRoYbsolDRfjy4fMC2qItkR7r
ax1kNwfwocoXJeEdESludulT8aujfYjLqa/a4Mcp1WqTAkf3rVY6w4YjyRmHfVdPq4sd9QIDAQAB
MA0GCSqGSIb3DQEBBAUAA4GBAE4sHGEH88tFKvh2a2sTm1w1rEhlAVaPQX+zXN4EK1zicT+04hB+
5vb3ssVtmJl+MI/O7xtEOqvnyH9ykVTy0QWEOwJx5AgLle1ST9hTt/lD3bGuoUCAAOYw/C4qa4ml
Ou2KHczyOoB/laBe8Lu9r6KpTogO84qij3DhQElVZt5J
-----END CERTIFICATE-----
';

// A sample message as would be in the $_GET['msg'] querystring param of the
// request to your session receiver script
$message = urlencode('AAAAEIMCL5IWCmcnEnQj8w5gH1rWm2R1hCb8X+HYAYQTS19wAS1bW1e1d8rGppD4Gr6zmBMncn0cXjng4lmOA/d/mnDviULLQeJJpwsyOoc0p+bT2EVEJYXXQNBZlZiDpylGvpsVLzmU9INNiYiMfW+vet106JF4rmwJg/1Y1QcCsKOTcklIxt2h2bi2pFQsmqq0urIZtOEWYWeadjpBCGfjVYEtHR3zRvbCSrK+aHVLDQk02WrLz7iJc/+6NfF2t6YgSjvNNmTo8ls5vzQR95xu7TDV7YOkwaGbf2Kk0TlGs2FmmGatMGZPU324l3oH64m7bs02N4tXCLwroXsM/VU0rDw4uFuNNAQ1PGwVk6hEHk9FpCZ2Oz+iFDLyAAvIwRSBbXKmc3bagoJ/OHuKnXrctFOIh3LEXwuJ+U948TAm8xcffBsGgbm4RZOl6DUv9vFglnfCcIcj63gOeI5RBJL1P7rxMIALf9nxZuVeDkc3kJDtWzC2o+mRbWm3kmCcQFfBEWjgf53EjzcEeFDbRTgnqdlLO6Heppr1eqpU2Vhm/cxf6D6Ur17iJm5Hdp/2rZTaZn3JlYDN5JsKnQTKGigry96uQQE0ztLLhUlxlug6oul0wkTYzXrFPXgJGMNwFC/9sv+PLzNjq2ApTpI+WeaH440EueZ7SUuiAcGvEaI5eo67YCzEjF0z8Iihkl1ZWG8igmozXS+xFToiSthpFAbXJscB0Ycc2QGOc2ZVmbEJZEqnTmKpnJyy6Og2qFqbktxFGwNyj0V0ukpkorrrotaBFjfVYDPGWe/9AFxpvm9A4Jj5UKhDuQrHZO7obsvjuDKD9g==');

// A sample signature as would be in the $_GET['sig'] querystring param of the
// request to your session receiver script
$signature = urlencode('P8Uyl0j/ZpSwmTa412eVK/VLAMdHuNZP5wVeZm5bmK8hbWDo2QlMHbh6XLWmFSc8HMK7jPHMEpnGHMdg9x/mhmCs9GMvbYQOWZkIsIeBzdOmp+LhZWqCQNK8juauB81FKbs0bvPsSwulx1565o4eozPKPRWBULLTKhrto1qfF8o=');

// The following 2 variable assignments are commented out as they illustrate the
// system working with gzipped parameters. If you want to use gzipped parameters
// make sure you send true to the 3rd parameter of the IbmPwSec::getMessage()
// method ($isGzipped)

// A sample gzipped message as would be in the $_GET['gzmsg'] querystring param
// of the request to your session receiver script ()
$gzmessage = 'AAAAEHSQn01kXHYALs8aCWGMab7CMqmJFKk8dsbX9+68LbNgODSyv9u7g4aUJngSxj8wVPAFcNyiKEm6yWMVoViheWvVmxvqU84fGVhHjpG7vo94ENqpOuSUBKcifERiW35Et6f4LfkCJiKjCokl+JaurNpeij9cJf8YZFixFWXWJSf+1BvLtVL+SMy/EunT0VKLN/1pq170zxWMiUJ2v868FJcarCaq5Gw3/5RanyaA9TxT512OZNBMdG3p7dLKKNTkdMXBFVT4SMHUnds8xi+YSanwuQ3U74fEiBis1ODYTY1QXtJAb8h0RFQ3Yt7M/90qT7Nyd0RKNkUYmuNE8rp+ixg4s30c0r+4XxpcZLwXdJau2WvmJSgC7npshRtpfPyIUtPOmfVHahirkwvaGKuIJw8PxnpdxJSnYzjC0LQZXQPTrMpTYUedIZTdFuCfJXZwbmN13pkqRCACYeAZPpGc9kaY+vkr/L/em2PdNqmht8H8';

// A sample gzipped signature as would be in the $_GET['gzsig'] querystring
// param of the request to your session receiver script
$gzsignature = 'JftCHkPrn2qCuTQf/PA83WnMCBbeL0SztBI2L1pu95xpv8BJoCXt6ueOGr4+CWMu60CrhAutn2Tqii0QdPoJahzVV0zXaXCFK08hjc3uGnL+B07x+8rRFHBrV72fUcI91LAfOU9kf9rqIYGk61KFCZHVjnzPCaBniY4QGxNfrQU=';

// Your password provided by IBM
$password = 'secretPassphrase';

// Your vendor code provided by IBM
$vendorCode = 'ibm_pw_vendorcode';

// That's the end of the section that initialises all the variables we need, now
// we get to the meaty stuff...

require_once 'ibm_pw_sec.php';

// Pear's Log class
require_once 'Log.php';

// Create a concrete log handler object from Pear Log. This example uses the
// file log handler and writes to a file out.log in the current directory.
$Logger = Log::factory('file', 'out.log');

// Set the Logger object as a static property in the custom Exception class the
// library uses so it's available whenever a new IbmPwSecException is thrown.
IbmPwSecException::setLogger($Logger);

// Create a concrete instance of your chosen signature cache method, which is a
// dependency of the IbmPwSec class, ready to inject it into the IbmPwSec class.
// In this case we're caching the signatures on the file system so we're
// creating an instance of the IbmPwSec_SignatureCache_File class, which
// requires a path to the signature cache file to use in the options array
// passed to the constructor. Here, we're going to cache the signatures in a
// file called 'signatures' in this directory.
$SignatureCache = new IbmPwSec_SignatureCache_File(array('path' => 'signatures'));

// Create a concrete instance of your chosen decryptor method, which is a
// dependency of the IbmPwSec class, ready to inject it into the IbmPwSec class.
// In this case we're going to use the AES decryption algorithm, and we need to
// supply it with the password IBM provide
$Decryptor = new IbmPwSec_Decryptor_Aes($password);

// Finally, we have everything ready to create a new IbmPwSec object and call
// the IbmPwSec::getMessage() method.
$IbmPwSec = new IbmPwSec($SignatureCache, $Decryptor, $certificate, $vendorCode);

// Wrap the IbmPwSec::getMessage() call in a try/catch block so you can handle
// any Exceptions thrown however you want. It is suggested that you redirect the
// user to the IBM Partner World site, but we won't do that here, as we want to
// show any Exceptions
try {
  // Comment/Uncomment the next 2 lines to test non/gzipped params respectively
  $message = $IbmPwSec->getMessage($message, $signature);
//  $message = $IbmPwSec->getMessage($gzmessage, $gzsignature, true);
  echo '<h1>Success</h1>'.PHP_EOL;
  echo '<p>It worked, here\'s the message:</p>'.PHP_EOL;
  echo '<p><pre>'.htmlentities($message).'</pre></p>'.PHP_EOL;
} catch (IbmPwSecException $e) {
  echo '<h1>Your attempted hack was an epic fail</h1>'.PHP_EOL;
  echo '<p>'.$e->getMessage().'</p>'.PHP_EOL;
  echo '<p>You\'d normally be redirected to IBM Partner World now</p>';
} catch (Exception $e) {
  echo '<h1>Something went wrong, google the message:</h1>'.PHP_EOL;
  echo '<p>'.$e->getMessage().'</p>'.PHP_EOL;
}

// Check the signature cache file and the log file to make sure they are working