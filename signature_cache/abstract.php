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
 * Abstract class for signature cache functionality for the PHP IBM Partner
 * World Session Exchange library.
 *
 * Signatures could conceivably be cached on the file system, in a database or
 * in memcache etc. Specific signature cache implementations should extend this
 * abstract class.
 */
abstract class IbmPwSec_SignatureCache_Abstract {

  /**
   * The duration in seconds for how long signatures should be cached to ensure
   * duplicate signatures are not allowed through
   */
  const SIGNATURE_EXPIRY = 180;

  /**
   * Settings of the signature cache engine
   * 
   * @var array
   */
  protected $_settings;

  /**
   * Sets passed options in the $_settings property.
   * 
   * @param array $options
   */
  public function __construct(array $options) {
    $this->_settings = $options;
  }

  /**
   * Abstract method that all concrete subclasses should implement to check the
   * uniqueness of the signature.
   *
   * Concrete implementations should accept a signature and return true if it is
   * a duplicate and false if it is not. This means the method not only has to
   * handle the logic for checking if it's a duplicate, it also has to handle
   * the storage and retrieval of the previously received signatures to and from
   * the cache.
   */
  abstract public function isDuplicate($signature);
  
}