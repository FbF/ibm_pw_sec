<?php
/**
 * PHP IBM PartnerWorld Session Exchange Library
 *
 * @author Neil Crookes
 * @copyright Neil Crookes
 * @package IbmPwSec
 * @subpackage IbmPwSec.SignatureCache
 * @license http://www.opensource.org/licenses/mit-license.php The MIT License
 */

/**
 * Abstract class for decryptor functionality for the PHP IBM Partner World
 * Session Exchange library.
 *
 * Algorithms currently supported are AES (Rijndael-128) and 3DES
 */
abstract class IbmPwSec_Decryptor_Abstract {

  /**
   * The number of bytes containing the number representing the length of the
   * salt in bytes
   *
   * @var integer
   */
  protected $_saltLengthBytes = 4;

  /**
   * The decryption mode to use
   *
   * @var string
   */
  protected $_decryptionMode = 'cbc';

  /**
   * Passed in constructor
   *
   * @var string
   */
  protected $_password;

  /**
   * Passed in constructor
   *
   * @var string
   */
  protected $_decryptionAlgorithmDirectory;

  /**
   * Passed in constructor
   *
   * @var string
   */
  protected $_decryptionModeDirectory;

  /**
   * Checks the requested algorithms and modes are available and stores the
   * passed settings in the object properties
   *
   * @param string $password The shared password IBM supplied your vendor
   * @param string $decryptionAlgorithmDirectory The directory containing the
   *        encryption modules.
   * @param string $decryptionModeDirectory The directory containing the
   *        encryption modules.
   */
  public function __construct($password,
                              $decryptionAlgorithmDirectory = '',
                              $decryptionModeDirectory = '') {

    if (!extension_loaded('mcrypt')) {
      throw new Exception('MCrypt extension is not loaded and is needed for decrypting the message');
    }

    $algorithms = mcrypt_list_algorithms($decryptionAlgorithmDirectory);

    if (!in_array($this->_decryptionAlgorithm, $algorithms)) {
      throw new Exception('Decryption Algorithm Not Available');
    }

    $modes = mcrypt_list_modes($decryptionModeDirectory);

    if (!in_array($this->_decryptionMode, $modes)) {
      throw new Exception('Decryption Mode Not Available');
    }

    // Java strings are all UCS-2 Big Endian encoded so we need to convert the
    // password to that charset before MD5ing it to ensure we get the same key
    // as was used to encrypt the data.
    $currentEncoding = mb_detect_encoding($password);
    $passwordInUCS2BE = mb_convert_encoding($password, 'UCS-2BE', $currentEncoding);

    $this->_password = $passwordInUCS2BE;
    $this->_decryptionAlgorithmDirectory = $decryptionAlgorithmDirectory;
    $this->_decryptionModeDirectory = $decryptionModeDirectory;
    
  }

  /**
   *
   * @param string $message
   * @return string
   */
  public function decrypt($message) {

    // Get the salt and cipher text from the message body
    list($salt, $cipherText) = $this->_getSaltCipherText($message);

    // Get the raw key from the password for use in decrypting the cipher text
    $key = $this->_getKey();

    $td = mcrypt_module_open($this->_decryptionAlgorithm,
                             $this->_decryptionAlgorithmDirectory,
                             $this->_decryptionMode,
                             $this->_decryptionModeDirectory);
		if ($td != true) {
      throw new Exception('Could not open mcrypt module with given algorithm and mode');
    }

		if (mcrypt_generic_init($td, $key, $salt) !== 0) {
      throw new Exception('Could not initialize buffers for decryption');
    }

		if (!($decoded = mdecrypt_generic($td, $cipherText))) {
      throw new IbmPwSecException('Could Not Decrypt Message');
    }

    // Clean up
		mcrypt_generic_deinit($td);
		mcrypt_module_close($td);

    // Remove padding that is added to the original during encryption to ensure
    // that all the blocks are the same length (as required for Cypher Block
    // Chaining mode).
		$decoded = $this->_pkcs5_unpad($decoded);

    return $decoded;
    
  }

  /**
   * Remove padding that is added to the original during encryption to ensure
   * that all the blocks are the same length (as required for Cypher Block
   * Chaining mode).
   * 
   * @param string $text
   * @return string
   */
  protected function _pkcs5_unpad($text) {
    // Get the pad character, which is the last character of the string (PKCS5
    // assumes there will always be padding)
    $padChar = substr($text, -1);
    // Get the length of the padding, which is the ascii value of the pad
    // character
    $padLength = ord($padChar);
    // Return the given text with the padding removed
    return substr($text, 0, -1 * $padLength);
  }

  /**
   * Extracts the salt (used to decrypt the cipher text) and cipher text form
   * the message body and returns them both in an array, salt first, then cipher
   * text. Throws IbmPwSecException if salt length is not 16.
   *
   * @param string $message The message param supplied by IBM in the request
   * @return array array(salt, ciphertext)
   */
  protected function _getSaltCipherText($message) {

    $message = base64_decode($message);

    // The msg in now a binary string, grab the first 4 bytes and convert it to
    // a hex string, and from there to a decimal / integer
    $saltLength = hexdec(bin2hex(substr($message, 0, $this->_saltLengthBytes)));
    
    // Check the salt length is 16 (bytes)
    if ($saltLength != $this->_saltLength) {
      throw new IbmPwSecException('Invalid Salt Length');
    }

    // Extract the salt from the msg (start at pos 4, i.e. the 5th byte and grab
    // the next 16 bytes)
    $salt = substr($message, $this->_saltLengthBytes, $this->_saltLength);

    // Extract the cipher text from the msg (start at pos 20, i.e. salt length,
    // 4, plus salt bytes, 16, equals 20, until the end of the string)
    $cipherText = substr($message, $this->_saltLengthBytes + $this->_saltLength);

    return array($salt, $cipherText);

  }

  abstract protected function _getKey();
  
}