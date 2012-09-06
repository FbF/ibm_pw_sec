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
 * Concrete class that extends the Signature Cache abstract class and implements
 * signature cache and duplicate signature checking functionality by storing
 * signatures on the file system in a file whose path is defined in the options
 * array passed to the constructor.
 */
class IbmPwSec_SignatureCache_File extends IbmPwSec_SignatureCache_Abstract {

  /**
   * Sets passed options in the $_settings property. Ensure the path option is
   * set.
   *
   * @param array $options
   */
  public function __construct(array $options) {
    if (empty($options['path'])) {
      throw new Exception("The 'path' key must be specified in the options array with the value being the path to the file on the file system in which you wish to store the signatures");
    }
    if (is_dir($options['path'])) {
      throw new Exception("The 'path' key must be a file");
    }
    parent::__construct($options);
  }

  /**
   * Returns true if the given signature has been supplied before in the expiry
   * time, or false if it hasn't.
   *
   * This is achieved by keeping track of the signatures and the timestamps they
   * were received in a signatures cache file, the path to which you can
   * define in the options array passed to the class constructor.
   *
   * The signatures cache file contains 1 line per signature, the line contains
   * the timestamp the signature was received, then a space, then the signature
   * itself. The most recent signature is at the top.
   *
   * @param string $signature
   * @return boolean True is bad, false is good
   */
  public function isDuplicate($signature) {

    $isDuplicateSignature = false;

    // Check if the signature cache file is readable
    if (file_exists($this->_settings['path'])) {
      if (!is_readable($this->_settings['path'])) {
        throw new Exception('Could not read from signature cache file');
      }
    } elseif (!is_readable(dirname($this->_settings['path']))) {
      throw new Exception('Could not read from signature cache file directory');
    }

    // Get the previously received signatures from the cache file
    if (file_exists($this->_settings['path'])) {
      $previousSignatures = file_get_contents($this->_settings['path']);
    }
    
    $now = time();

    // Initialise the still valid signatures var, that will be written back to
    // the cache file, with the current signature
    $stillValidSignatures = $now . ' ' . $signature . PHP_EOL;

    if (!empty($previousSignatures)) {

      $expiry = $now - self::SIGNATURE_EXPIRY;

      $lines = explode(PHP_EOL, $previousSignatures);

      // Iterate through the previous signature lines from the cache file, if
      // the timestamp is older than the expiry time, there's no need to
      // continue checking any more lines since if there was a duplicate
      // signature from before, it'll fail the valid signature test. If the
      // timestamp is not older than the expiry, add the line to the string
      // containing the list of still valid signatures to write back to the
      // cache file. If the current signature is the same as the previous one,
      // set the isDuplicateSignature var to true before returning at the end.
      foreach ($lines as $line) {
        if (empty($line)) {
          continue;
        }
        list($previousSignatureTimestamp, $previousSignature) = explode(' ', $line);
        if ($previousSignatureTimestamp < $expiry) {
          break;
        }
        $stillValidSignatures .= $line . PHP_EOL;
        if ($previousSignature == $signature) {
          $isDuplicateSignature = true;
        }
      }

    }

    // Check if the signature cache file is writable
    if (file_exists($this->_settings['path'])) {
      if (!is_writable($this->_settings['path'])) {
        throw new Exception('Could not write to signature cache file');
      }
    } elseif (!is_writable(dirname($this->_settings['path']))) {
      throw new Exception('Could not write to signature cache file directory');
    }

    // Write the still valid signatures back to the cache file
    file_put_contents($this->_settings['path'], $stillValidSignatures);

    return $isDuplicateSignature;

  }

}