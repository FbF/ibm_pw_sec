<?php
/**
 * PHP IBM PartnerWorld Session Exchange Library
 *
 * @author Neil Crookes
 * @copyright Neil Crookes
 * @package IbmPwSec
 * @license http://www.opensource.org/licenses/mit-license.php The MIT License
 */

// Load main file containing autoload function and Exception class
require_once dirname(__FILE__) . '/../../ibm_pw_sec.php';

// Load PEAR Log
require_once 'Log.php';

/**
 * Test for AES Decryptor
 */
class IbmPwSec_Decryptor_AesTest extends PHPUnit_Framework_TestCase {

  /**
   * Called before each test. Sets the exception logger to a stub of the Pear
   * Log class so that when IbmPwSecExceptions are thrown, we don't actually
   * write them to the exception log
   */
  public function  setUp() {

    parent::setUp();

    $LoggerStub = $this->getMock('Log', array(), array(), '', false);

    IbmPwSecException::setLogger($LoggerStub);

  }

  /**
   * Test decryption using the AES Decryptor class
   */
  public function testDecrypt() {

    $IbmPwSec_Decryptor_Aes = new IbmPwSec_Decryptor_Aes('secretPassphrase');

    $message = 'AAAAEIMCL5IWCmcnEnQj8w5gH1rWm2R1hCb8X+HYAYQTS19wAS1bW1e1d8rGppD4Gr6zmBMncn0cXjng4lmOA/d/mnDviULLQeJJpwsyOoc0p+bT2EVEJYXXQNBZlZiDpylGvpsVLzmU9INNiYiMfW+vet106JF4rmwJg/1Y1QcCsKOTcklIxt2h2bi2pFQsmqq0urIZtOEWYWeadjpBCGfjVYEtHR3zRvbCSrK+aHVLDQk02WrLz7iJc/+6NfF2t6YgSjvNNmTo8ls5vzQR95xu7TDV7YOkwaGbf2Kk0TlGs2FmmGatMGZPU324l3oH64m7bs02N4tXCLwroXsM/VU0rDw4uFuNNAQ1PGwVk6hEHk9FpCZ2Oz+iFDLyAAvIwRSBbXKmc3bagoJ/OHuKnXrctFOIh3LEXwuJ+U948TAm8xcffBsGgbm4RZOl6DUv9vFglnfCcIcj63gOeI5RBJL1P7rxMIALf9nxZuVeDkc3kJDtWzC2o+mRbWm3kmCcQFfBEWjgf53EjzcEeFDbRTgnqdlLO6Heppr1eqpU2Vhm/cxf6D6Ur17iJm5Hdp/2rZTaZn3JlYDN5JsKnQTKGigry96uQQE0ztLLhUlxlug6oul0wkTYzXrFPXgJGMNwFC/9sv+PLzNjq2ApTpI+WeaH440EueZ7SUuiAcGvEaI5eo67YCzEjF0z8Iihkl1ZWG8igmozXS+xFToiSthpFAbXJscB0Ycc2QGOc2ZVmbEJZEqnTmKpnJyy6Og2qFqbktxFGwNyj0V0ukpkorrrotaBFjfVYDPGWe/9AFxpvm9A4Jj5UKhDuQrHZO7obsvjuDKD9g==';

    $actual = $IbmPwSec_Decryptor_Aes->decrypt($message);

    $expected = '<SignonRequest vendor="ibm_pw_vendorcode"><LoggedOnUser><Name><PrimeSurname>Muggs</PrimeSurname><FirstName>J. Fred</FirstName></Name><UniqueId>123456789A</UniqueId><Email>fred_muggs@bananas.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence></LoggedOnUser><PartnerDetails><CompanyId>18z7gsgn</CompanyId><TradeStyleName>We Have Bananas, Inc</TradeStyleName></PartnerDetails><SignonRequestDetails><Timestamp>2010-01-18 17:18:06 GMT</Timestamp><Expiration>2015-01-18 17:21:06 GMT</Expiration><SessionID>1234ABCD</SessionID></SignonRequestDetails></SignonRequest>';

    $this->assertEquals($expected, $actual);

  }

}