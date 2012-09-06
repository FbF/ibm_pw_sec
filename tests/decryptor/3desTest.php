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
 * Test for 3DES Decryptor
 */
class IbmPwSec_Decryptor_3desTest extends PHPUnit_Framework_TestCase {

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
   * Test decryption using the 3DES Decryptor class
   */
  public function testDecryptWithValidMessage() {

    $IbmPwSec_Decryptor_3des = new IbmPwSec_Decryptor_3des('secretPassphrase');

    $message = urldecode('AAAACMrKHyzL7Jew16wPyxo%2FXTg0Albex7ATyB022%2FxaPntVS%2FEGeflDZYDBjSOzsvtZWmtC3lRi2t8mFGmj%2BotnaRUgYzSmVkzL52Ox72U1D8CFTTqbYU%2BWHIns28p7HxHprV830i5sONg%2BI6Pz70knGH7YDOaF1vIn0GBAPmI%2F94MS%2FdH4xOaEvUqqGAzAUcaxpuMFiSizAswKvPkQBPzknXCIRA7rAn1TvlEI9%2FNRJ47aW1O4vbTL2WipWgGTA%2BU2u%2FUJUXLMQh5qEwFi5k7k2HO2Yy9DO3737SDP%2FUUFdsUvL26vMmaH235iD%2FK3lwz%2FPFPa7m49rqm1c5eBmzziippBZqSAIaMbdbJtHXyGtlKBDJAO1Zg8d3emzUs5PuCVIchMKW9ALJH%2BXD857JlV9Nnaipsz7GvWGidjOW8H8XGW0PpY78orMDgAQ3gjUSe4Tipps4RRqHx0ovqwgFejsy6N8PqZ7XZa9N3fJPueoMQssyHGO6peYC70oi4qlEhop35XjsT1gy8h%2FzEewrDM9eWhLv5DHO6K3Jj9tTzxRbz38Tri6lazKGTJ0L4SIZ46JRIhTHnH7Dwhm2O5Gi%2Fk%2BvYn7P3n2HAzDNJ%2BKbT4gxLXi73w1tkCLsC25M0WAXbaW%2F6%2B3oKF6XLDvlZni3oL59fToHLbZh6s%2FZM%2FDPb6K3FH2b5jz7%2BhIPJT%2BsXjwU1Z6gM5kjk%2Flkhm6ZjMAaFAb%2FEu4JSVVFT5utbqw%2F3KbvnLMdvnyIMn%2BLXb8jPurAw6No9MkeK20JvXRZlZw2X3VxKBx9O04qjm5izywQOekCdtBfoRzZITT88jKxxtzl4AaDnaWMGXc4xkUhytrfmUsmiynFiaeVKWCqwUWwRAVXMK');

    $actual = $IbmPwSec_Decryptor_3des->decrypt($message);

    $expected = '<SignonRequest vendor="ibm_pw_vendorcode"><LoggedOnUser><Name><PrimeSurname>Case 1</PrimeSurname><FirstName>Test</FirstName></Name><UniqueId>T000000101</UniqueId><Email>testcase1@nowhere.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence><PreferredLanguageCode>en</PreferredLanguageCode></LoggedOnUser><PartnerDetails><CompanyId>1</CompanyId><TradeStyleName>Test Case 1</TradeStyleName></PartnerDetails><SignonRequestDetails><Timestamp>2010-08-13 14:40:13 GMT</Timestamp><Expiration>2015-08-13 14:43:13 GMT</Expiration><SessionID>BvxSsarsQhdxJm2KgTkbuoK</SessionID></SignonRequestDetails></SignonRequest>';

    $this->assertEquals($expected, $actual);

  }

}