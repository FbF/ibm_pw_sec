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
 * Main class for the IBM Partner World Session Exchange functionality.
 */
class IbmPwSec {

  /**
   * Passed in constructor
   *
   * @var IbmPwSec_SignatureCache_Abstract
   */
  protected $_SignatureCache;

  /**
   * Passed in constructor
   *
   * @var IbmPwSec_Decryptor_Abstract
   */
  protected $_Decryptor;

  /**
   * Passed in constructor
   *
   * @var mixed
   */
  protected $_certificate;

  /**
   * Passed in constructor
   *
   * @var string
   */
  protected $_vendorCode;

  /**
   * Stores the passed settings
   *
   * @param IbmPwSec_SignatureCache_Abstract $SignatureCache An instance of a
   *        concrete class that extends the IbmPwSec_SignatureCache_Abstract
   *        abstract class and implements the isDuplicate() method.
   * @param IbmPwSec_Decryptor_Abstract $Decryptor An instance of a concrete
   *        class that extends the IbmPwSec_Decryptor_Abstract abstract class
   *        and implements the decrypt() method.
   * @param mixed $certificate Can be one of the following:
   *        - an X.509 certificate resource
   *        - a string having the format file://path/to/file.pem. The named file
   *        must contain a PEM encoded certificate/private key (it may contain
   *        both).
   *        - A PEM formatted private key.
   * @param string $vendorCode The vendor code assigned to you by IBM
   */
  public function __construct(IbmPwSec_SignatureCache_Abstract $SignatureCache,
                              IbmPwSec_Decryptor_Abstract $Decryptor,
                              $certificate,
                              $vendorCode) {

    if (!extension_loaded('openssl')) {
      throw new Exception('OpenSSL extension is not loaded and is needed for verifying the signature');
    }
    
    $this->_SignatureCache = $SignatureCache;
    $this->_Decryptor = $Decryptor;
    $this->_certificate = $certificate;
    $this->_vendorCode = $vendorCode;
  }

  /**
   * Returns the decoded XML sign on request if the message and signature are
   * valid, or throws various Exceptions if not.
   *
   * @param string $message The message param supplied by IBM in the request
   * @param string $signature The signature param supplied by IBM in the request
   * @param boolean $isGzipped Whether the message was gzipped before encryption
   * @return string The decoded message string
   */
  public function getMessage($message, $signature, $isGzipped = false) {

    if ($this->_SignatureCache->isDuplicate($signature)) {
      throw new IbmPwSecException('Duplicate Signature');
    }

    if (!$this->_verifySignature($message, $signature)) {
      throw new IbmPwSecException('Invalid Signature');
    }

    $decodedMessage = $this->_Decryptor->decrypt($message);

    if ($isGzipped) {
      // PHP's builtin gzuncompress() function would not work, so alternatively
      // this approach uses stream wrappers comress.zlib: to uncompress the
      // string and data: to get the string into a stream. Since the
      // $decodedMessage is a binary string, we also have to base64_encode() it
      // before reading it, and add base64 conversion filter to the stream.
      $decodedMessage = file_get_contents("compress.zlib://data://text/plain;base64," . base64_encode($decodedMessage));
    }

    $this->_validateMessage($decodedMessage, $this->_vendorCode);

    return $decodedMessage;

  }

  /**
   * Verifies the given signature is valid for the given message and public key.
   * Throws Exception if could not get public key from the certificate.
   *
   * @return boolean True on success, false on failure
   */
  protected function _verifySignature($message, $signature) {

    if (!($pubKeyId = openssl_get_publickey($this->_certificate))) {
      throw new Exception('Could not get public key id from supplied certificate');
    }

    $data = utf8_decode($message);
    
    $signature = base64_decode($signature);

    $result = openssl_verify($data, $signature, $pubKeyId, OPENSSL_ALGO_MD5);
    
    return $result == 1;
    
  }

  /**
   * Validates the decoded message is a proper XML document with root node
   * SignonRequest, valid vendor code and valid timestamp and expiration values.
   * Throws IbmPwSecException if any errors are encountered.
   *
   * @param string $decodedMessage The decoded message string containing the
   *        SignonRequest data
   * @param string $vendorCode The vendor code assigned to you by IBM
   * @param string $now Current date/time in the format 'Y-m-d H:i:s \G\M\T'
   * @return boolean True
   */
  protected function _validateMessage($decodedMessage, $vendorCode, $now = null) {

    // Turn off XML error reporting so simplexml_load_string() won't throw a
    // warning if the string is not valid XML.
    libxml_use_internal_errors(true);
    if (($xml = simplexml_load_string($decodedMessage)) === false) {
      throw new IbmPwSecException('Invalid XML');
    }

    // Check root node is SignonRequest
    if ($xml->getName() != 'SignonRequest') {
      throw new IbmPwSecException('Invalid XML Root Node');
    }

    // Check vendor code is the one IBM have supplied us with
    if (isset($xml['vendor']) && $xml['vendor'] != $vendorCode) {
      throw new IbmPwSecException('Invalid Vendor Code');
    }

    // Get current date/time if not specified to check timestamp and expiry
    // against (see below)
    if (!$now) {
      $now = gmdate('Y-m-d H:i:s \G\M\T');
    }

    // Check signon request was not created in the future (suggests tampering)
    if (!isset($xml->SignonRequestDetails->Timestamp)) {
      throw new IbmPwSecException('No Timestamp');
    }
    $timestamp = $xml->SignonRequestDetails->Timestamp;
    if ($timestamp > ($now + 60)) {
      throw new IbmPwSecException('Invalid Timestamp');
    }

    // Check signon request has not expired
    if (!isset($xml->SignonRequestDetails->Expiration)) {
      throw new IbmPwSecException('No Expiration');
    }
    $expiration = $xml->SignonRequestDetails->Expiration;
    if ($expiration < ($now - 60)) {
      throw new IbmPwSecException('Invalid Expiration');
    }

    return true;

  }

}

/**
 * Custom Exception class that logs all exceptions.
 *
 * You must call IbmPwSecException::setLogger() and pass it a Pear Log object
 * before a new IbmPwSecException is thrown.
 */
class IbmPwSecException extends Exception {

  /**
   * Instance of the Pear Log class
   *
   * @var Log object
   */
  protected static $_Logger;

  /**
   * Called when a new IbmPwSecException gets thrown and logs the message and
   * code using the Pear Log object in the static $_Logger property, which you
   * can set using setLogger() static method.
   *
	 * @param string $message The message to log
	 * @param integer $code The severity of the issue. Pear Log severity levels
   *        are used, e.g. PEAR_LOG_EMERG, which are defined at the top of the
   *        Pear Log class definition file.
	 * @param Exception $previous The previous exception used for the exception
   *        chaining.
   */
  public function __construct($message = null, $code = null) {
    parent::__construct($message, $code);
    // Log the exception message
    self::$_Logger->log($message, $code);
  }

  /**
   * Static method which stores a Pear Log object in the protected static
   * property $_Logger, on which the log() method is called in the constructor
   * when a new IbmPwSecException is thrown.
   *
   * @param Log $Logger Instance of Pear Log class
   */
  public static function setLogger(Log $Logger) {
    self::$_Logger = $Logger;
  }
  
}

/**
 * Autoload function converts underscores to directory separators and CamelCase
 * to lowercase_underscore_separated paths for a given class name.
 *
 * For example, for a class name IbmPwSec_SignatureCache_File the file at
 * ../ibm_pw_sec/signature_cache/file.php will be included.
 *
 * @param string $className
 */
function ibmPwSecAutoLoad($className) {
  $filename = str_replace('_', DIRECTORY_SEPARATOR, $className);
  $filename = preg_replace('/([a-z])([A-Z])/', '$1_$2', $filename);
  $filename = strtolower($filename);
  $filename = dirname(dirname(__FILE__)) . DIRECTORY_SEPARATOR . $filename . '.php';
  if (file_exists($filename)) {
    include $filename;
  }
}
spl_autoload_register('ibmPwSecAutoLoad');