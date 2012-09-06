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
 * Concrete class that extends the Decryptor abstract class and implements
 * decryption using the AES (Rijndael 128) algorithm.
 */
class IbmPwSec_Decryptor_Aes extends IbmPwSec_Decryptor_Abstract {

  /**
   * The length of the salt in bytes
   *
   * @var integer
   */
  protected $_saltLength = 16;

  /**
   * The decryption algorithm to use
   */
  protected $_decryptionAlgorithm = 'rijndael-128';

  /**
   * Returns the key for use in decrypting the cipher text along with the salt,
   * from the given password.
   *
   * @return string
   */
  protected function _getKey() {

    $key = md5($this->_password, true);

    return $key;

  }

}