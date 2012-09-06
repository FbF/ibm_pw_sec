<?php
/**
 * PHP IBM PartnerWorld Session Exchange Library
 *
 * @author Neil Crookes
 * @copyright Neil Crookes
 * @package IbmPwSec
 * @license http://www.opensource.org/licenses/mit-license.php The MIT License
 */

// Load subject under test
require_once dirname(__FILE__) . '/../ibm_pw_sec.php';

// Load PEAR Log
require_once 'Log.php';

/**
 * Test case for the IbmPwSec class
 */
class IbmPwSecSignatureTest extends PHPUnit_Framework_TestCase {
  
  public function  setUp() {

    parent::setUp();

    $LoggerStub = $this->getMock('Log', array(), array(), '', false);

    IbmPwSecException::setLogger($LoggerStub);

    $this->SignatureCacheStub = $this->getMockForAbstractClass('IbmPwSec_SignatureCache_Abstract', array(), '', false);

    $this->DecryptorStub = $this->getMock('IbmPwSec_Decryptor_Aes', array(), array(), '', false);

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

    $this->IbmPwSec = new IbmPwSec($this->SignatureCacheStub, $this->DecryptorStub, $certificate, 'ibm_pw_vendorcode');

  }

  public function testDuplicateSignature() {

    $this->SignatureCacheStub->expects($this->any())
                             ->method('isDuplicate')
                             ->will($this->returnValue(true));

    $this->setExpectedException('IbmPwSecException', 'Duplicate Signature');
    $this->IbmPwSec->getMessage('message', 'signature');
    
  }

  public function testInvalidSignature() {

    $this->SignatureCacheStub->expects($this->any())
                             ->method('isDuplicate')
                             ->will($this->returnValue(false));

    $message = 'AAAACEvCkU2AqOyrVmQklHWus741kvMTfMFMizhOCuosJFb88m3NWmZb%2BOXjxvDLGwVbTd8TpFRvN8Hw3qUEB5%2FV0K%2BcnrbynUxYNm7MMeBOTjNPNOWm65s1VMtE74aJrAuM3D08kpIxhPibf59nctY2XDA8Ivysj4NcsrIKYnbPJTEv9DYsU9KFuoTSXO7yCNkKFJVGilkidhBv6B2o%2BWEaISGuSUhrGqDB8W%2BMrQFJnIGhgPhkgrGkPM4jAPTHR4gTZBqnmcfCgTD%2Bj%2FyAbslje6Lx8I8OwMA%2BIrNeHubbayYZkVB8QsAqUQaILwvlCEndXGIG6AYTY6lzOlQguYS6HdiabP34iDqT63pKhHxKZ4Wrva7%2FkvGqH3eUMlm1SwRYBj8Fxjc2yhBsKM41V1PQLLybYTouEVSKUysIfa23US2gp7BbMOGD4G5cvz7%2FSICvbfoou338gcf%2FKQNXU8jTEgZ50PqLHf8%2FWkq7WGjYTzKDlUSwaB2vyNfgceMQ4T1iMbGYJXD4LldM9B2VvkFmBMb0McKuj%2B%2Ft4h%2BOVKUxA%2FtvnejT6I8%2F80yBfJT3ddx5sdyuVzBqSJgpT28MzlyfiW0mb%2Ff4aHLZPliiTqA%2BXsf8hGBVeh616Q%2Bx2O5OnuN0wnFX5lQ07U7A%2BtOAsRxGXl6NVuQqlNH1xxo1fG4bPe9O6a25idZF91Jy686in2iKsheT5DUCrQKK%2BkENscxbn7u6h11KeN9qndBEc0ptOWIbhrk5CKUApPvHJKWHndE%2Fc1n%2Fqyk0jmP9z0Qsx7oATDjFBfnCwBkHBUIxotxvi7NqMRPKOHbLzBJCr%2F33GVYEcUlCuUWWUTB6Of70XvP%2FXOwZoDgGVc84KINVrN%2BpikP1';

    $signature = 'LMCABffONRtc2by7XXvYtY1I%2BpxM2yZ40m1CK0W2cnboqEYSLGqglJev6AV6cg4MungY3Ic0qpe7AqEjwKyt3wxLoWsETddRg2Pka%2FygVCGn3mhOdjb3XljYeCFD4%2Bq2ipfQ7BZhwNaOGb3%2F2QGjwrfqLL3zfrp%2Bgqpg7x1raZI%3D';

    $this->setExpectedException('IbmPwSecException', 'Invalid Signature');

    $this->IbmPwSec->getMessage($message, $signature);

  }

  public function testGetMessageAesNoGz() {

    $this->SignatureCacheStub->expects($this->any())
                             ->method('isDuplicate')
                             ->will($this->returnValue(false));

    $expected = '<SignonRequest vendor="ibm_pw_vendorcode"><LoggedOnUser><Name><PrimeSurname>Muggs</PrimeSurname><FirstName>J. Fred</FirstName></Name><UniqueId>123456789A</UniqueId><Email>fred_muggs@bananas.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence></LoggedOnUser><PartnerDetails><CompanyId>18z7gsgn</CompanyId><TradeStyleName>We Have Bananas, Inc</TradeStyleName></PartnerDetails><SignonRequestDetails><Timestamp>2010-01-18 17:18:06 GMT</Timestamp><Expiration>2015-01-18 17:21:06 GMT</Expiration><SessionID>1234ABCD</SessionID></SignonRequestDetails></SignonRequest>';

    $this->DecryptorStub->expects($this->any())
                        ->method('decrypt')
                        ->will($this->returnValue($expected));

    $message = 'AAAAEIMCL5IWCmcnEnQj8w5gH1rWm2R1hCb8X+HYAYQTS19wAS1bW1e1d8rGppD4Gr6zmBMncn0cXjng4lmOA/d/mnDviULLQeJJpwsyOoc0p+bT2EVEJYXXQNBZlZiDpylGvpsVLzmU9INNiYiMfW+vet106JF4rmwJg/1Y1QcCsKOTcklIxt2h2bi2pFQsmqq0urIZtOEWYWeadjpBCGfjVYEtHR3zRvbCSrK+aHVLDQk02WrLz7iJc/+6NfF2t6YgSjvNNmTo8ls5vzQR95xu7TDV7YOkwaGbf2Kk0TlGs2FmmGatMGZPU324l3oH64m7bs02N4tXCLwroXsM/VU0rDw4uFuNNAQ1PGwVk6hEHk9FpCZ2Oz+iFDLyAAvIwRSBbXKmc3bagoJ/OHuKnXrctFOIh3LEXwuJ+U948TAm8xcffBsGgbm4RZOl6DUv9vFglnfCcIcj63gOeI5RBJL1P7rxMIALf9nxZuVeDkc3kJDtWzC2o+mRbWm3kmCcQFfBEWjgf53EjzcEeFDbRTgnqdlLO6Heppr1eqpU2Vhm/cxf6D6Ur17iJm5Hdp/2rZTaZn3JlYDN5JsKnQTKGigry96uQQE0ztLLhUlxlug6oul0wkTYzXrFPXgJGMNwFC/9sv+PLzNjq2ApTpI+WeaH440EueZ7SUuiAcGvEaI5eo67YCzEjF0z8Iihkl1ZWG8igmozXS+xFToiSthpFAbXJscB0Ycc2QGOc2ZVmbEJZEqnTmKpnJyy6Og2qFqbktxFGwNyj0V0ukpkorrrotaBFjfVYDPGWe/9AFxpvm9A4Jj5UKhDuQrHZO7obsvjuDKD9g==';

    $signature = 'P8Uyl0j/ZpSwmTa412eVK/VLAMdHuNZP5wVeZm5bmK8hbWDo2QlMHbh6XLWmFSc8HMK7jPHMEpnGHMdg9x/mhmCs9GMvbYQOWZkIsIeBzdOmp+LhZWqCQNK8juauB81FKbs0bvPsSwulx1565o4eozPKPRWBULLTKhrto1qfF8o=';


    $actual = $this->IbmPwSec->getMessage($message, $signature);

    $this->assertEquals($expected, $actual);

  }

}

class IbmPwSecValidateMessageTest extends PHPUnit_Framework_TestCase {

  public function setUp() {
    parent::setUp();

    $LoggerStub = $this->getMock('Log', array(), array(), '', false);

    IbmPwSecException::setLogger($LoggerStub);

    $this->SignatureCacheStub = $this->getMockForAbstractClass('IbmPwSec_SignatureCache_Abstract', array(), '', false);

    // Configure the stub to return false when isDuplicate called
    $this->SignatureCacheStub->expects($this->any())
                             ->method('isDuplicate')
                             ->will($this->returnValue(false));

    $this->DecryptorStub = $this->getMock('IbmPwSec_Decryptor_Aes', array(), array(), '', false);

    $this->IbmPwSec = $this->getMock('IbmPwSec', array('_verifySignature'), array($this->SignatureCacheStub, $this->DecryptorStub, 'certificate', 'ibm_pw_vendorcode'));

    // Configure the stub to return true when _verifySignature called
    $this->IbmPwSec->expects($this->any())
                   ->method('_verifySignature')
                   ->will($this->returnValue(true));
  }
  
  public function testInvalidXml() {

    $this->DecryptorStub->expects($this->any())
                        ->method('decrypt')
                        ->will($this->returnValue('Invalid XML'));

    $this->setExpectedException('IbmPwSecException', 'Invalid XML');
    $actual = $this->IbmPwSec->getMessage('message', 'signature');
    
  }

  public function testInvalidXmlRootNode() {

    $this->DecryptorStub->expects($this->any())
                        ->method('decrypt')
                        ->will($this->returnValue('<invalid_xml_root_node />'));

    $this->setExpectedException('IbmPwSecException', 'Invalid XML Root Node');
    $actual = $this->IbmPwSec->getMessage('message', 'signature');

  }

  public function testInvalidVendorCode() {

    $this->DecryptorStub->expects($this->any())
                        ->method('decrypt')
                        ->will($this->returnValue('<SignonRequest vendor="ibm_pw_vendorcode_bad"><LoggedOnUser><Name><PrimeSurname>Case 4</PrimeSurname><FirstName>Test</FirstName></Name><UniqueId>T000000104</UniqueId><Email>testcase4@nowhere.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence><PreferredLanguageCode>en</PreferredLanguageCode></LoggedOnUser><PartnerDetails><CompanyId>1</CompanyId><TradeStyleName>Test Case 4</TradeStyleName></PartnerDetails><SignonRequestDetails><Timestamp>2010-08-13 14:54:33 GMT</Timestamp><Expiration>2015-08-13 14:57:33 GMT</Expiration><SessionID>2AVcWrBekr7k9JeeYhI6Bqm</SessionID></SignonRequestDetails></SignonRequest>'));

    $this->setExpectedException('IbmPwSecException', 'Invalid Vendor Code');
    $actual = $this->IbmPwSec->getMessage('message', 'signature');

  }

  public function testNoTimestamp() {

    $this->DecryptorStub->expects($this->any())
                        ->method('decrypt')
                        ->will($this->returnValue('<SignonRequest vendor="ibm_pw_vendorcode"><LoggedOnUser><Name><PrimeSurname>Case 5</PrimeSurname><FirstName>Test</FirstName></Name><UniqueId>T000000105</UniqueId><Email>testcase5@nowhere.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence><PreferredLanguageCode>en</PreferredLanguageCode></LoggedOnUser><PartnerDetails><CompanyId>1</CompanyId><TradeStyleName>Test Case 5</TradeStyleName></PartnerDetails><SignonRequestDetails><Expiration>2015-08-13 15:01:42 GMT</Expiration><SessionID>Rv_sO1KuBBLo8w0lexUGNhg</SessionID></SignonRequestDetails></SignonRequest>'));

    $this->setExpectedException('IbmPwSecException', 'No Timestamp');
    $actual = $this->IbmPwSec->getMessage('message', 'signature');

  }

  public function testInvalidTimestamp() {

    $this->DecryptorStub->expects($this->any())
                        ->method('decrypt')
                        ->will($this->returnValue('<SignonRequest vendor="ibm_pw_vendorcode"><LoggedOnUser><Name><PrimeSurname>Case 5</PrimeSurname><FirstName>Test</FirstName></Name><UniqueId>T000000105</UniqueId><Email>testcase5@nowhere.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence><PreferredLanguageCode>en</PreferredLanguageCode></LoggedOnUser><PartnerDetails><CompanyId>1</CompanyId><TradeStyleName>Test Case 5</TradeStyleName></PartnerDetails><SignonRequestDetails><Timestamp>2011-08-13 14:58:42 GMT</Timestamp><Expiration>2015-08-13 15:01:42 GMT</Expiration><SessionID>Rv_sO1KuBBLo8w0lexUGNhg</SessionID></SignonRequestDetails></SignonRequest>'));

    $this->setExpectedException('IbmPwSecException', 'Invalid Timestamp');
    $actual = $this->IbmPwSec->getMessage('message', 'signature');

  }

  public function testNoExpiration() {

    $this->DecryptorStub->expects($this->any())
                        ->method('decrypt')
                        ->will($this->returnValue('<SignonRequest vendor="ibm_pw_vendorcode"><LoggedOnUser><Name><PrimeSurname>Case 2</PrimeSurname><FirstName>Test</FirstName></Name><UniqueId>T000000106</UniqueId><Email>testcase6@nowhere.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence><PreferredLanguageCode>en</PreferredLanguageCode></LoggedOnUser><PartnerDetails><CompanyId>1</CompanyId><TradeStyleName>Test Case 6</TradeStyleName></PartnerDetails><SignonRequestDetails><Timestamp>2010-08-13 15:06:37 GMT</Timestamp><SessionID>wRP1jVvT5M1wA5RtAlL10c3</SessionID></SignonRequestDetails></SignonRequest>'));

    $this->setExpectedException('IbmPwSecException', 'No Expiration');
    $actual = $this->IbmPwSec->getMessage('message', 'signature');

  }

  public function testInvalidExpiration() {

    $this->DecryptorStub->expects($this->any())
                        ->method('decrypt')
                        ->will($this->returnValue('<SignonRequest vendor="ibm_pw_vendorcode"><LoggedOnUser><Name><PrimeSurname>Case 2</PrimeSurname><FirstName>Test</FirstName></Name><UniqueId>T000000106</UniqueId><Email>testcase6@nowhere.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence><PreferredLanguageCode>en</PreferredLanguageCode></LoggedOnUser><PartnerDetails><CompanyId>1</CompanyId><TradeStyleName>Test Case 6</TradeStyleName></PartnerDetails><SignonRequestDetails><Timestamp>2010-08-13 15:06:37 GMT</Timestamp><Expiration>2010-08-13 15:07:37 GMT</Expiration><SessionID>wRP1jVvT5M1wA5RtAlL10c3</SessionID></SignonRequestDetails></SignonRequest>'));

    $this->setExpectedException('IbmPwSecException', 'Invalid Expiration');
    $actual = $this->IbmPwSec->getMessage('message', 'signature');

  }

  public function testValidXml() {

    $expected = '<SignonRequest vendor="ibm_pw_vendorcode"><LoggedOnUser><Name><PrimeSurname>Case 4</PrimeSurname><FirstName>Test</FirstName></Name><UniqueId>T000000104</UniqueId><Email>testcase4@nowhere.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence><PreferredLanguageCode>en</PreferredLanguageCode></LoggedOnUser><PartnerDetails><CompanyId>1</CompanyId><TradeStyleName>Test Case 4</TradeStyleName></PartnerDetails><SignonRequestDetails><Timestamp>2010-08-13 14:54:33 GMT</Timestamp><Expiration>2015-08-13 14:57:33 GMT</Expiration><SessionID>2AVcWrBekr7k9JeeYhI6Bqm</SessionID></SignonRequestDetails></SignonRequest>';

    $this->DecryptorStub->expects($this->any())
                        ->method('decrypt')
                        ->will($this->returnValue($expected));

    $actual = $this->IbmPwSec->getMessage('message', 'signature');

    $this->assertEquals($expected, $actual);

  }

}

class IbmPwSecDecryptorIntegrationTest extends PHPUnit_Framework_TestCase {

  public function testUncompressMessage() {

    $LoggerStub = $this->getMock('Log', array(), array(), '', false);

    IbmPwSecException::setLogger($LoggerStub);

    $SignatureCacheStub = $this->getMockForAbstractClass('IbmPwSec_SignatureCache_Abstract', array(array()));

    $SignatureCacheStub->expects($this->any())
                       ->method('isDuplicate')
                       ->will($this->returnValue(false));

    $DecryptorStub = $this->getMock('IbmPwSec_Decryptor_Aes', array(), array(), '', false);
    $DecryptorStub->expects($this->any())
                  ->method('decrypt')
                  ->will($this->returnValue('�       mQ�O�0�W�>�JQ6\�������ǥ�6[�ο�2"�Y�w�^��A ��5�Q��8Sw�K���J�,���,I0^ʍF�����`�D��Q�2[�Dia0Jg�Sך)��4���Ha��1�������C 5Ӕ�ۛ�۴Ը�qi��FY
��B���2��ھ�؞��ԥ.����(uZ�רE�2B�        �\����]qUHT,��.;�9��ҳ��Ot"�6������\'|E��5��_Yscm��"���hh�W<͙�P�v�M}���8=�a��5�_�P��,�^CwiM�Á �6�|r^�p4� i0_�Ԇ��|7XW  '));

    $IbmPwSec = $this->getMock('IbmPwSec', array('_verifySignature', '_validateMessage'), array($SignatureCacheStub, $DecryptorStub, 'certificate', 'vendor code'));

    $IbmPwSec->expects($this->any())
             ->method('_verifySignature')
             ->will($this->returnValue(true));

    $IbmPwSec->expects($this->any())
             ->method('_validateMessage')
             ->will($this->returnValue(true));

    $actual = $IbmPwSec->getMessage('message', 'signature', true);

    $expected = '<SignonRequest vendor="ibm_pw_vendorcode"><LoggedOnUser><Name><PrimeSurname>Muggs</PrimeSurname><FirstName>J. Fred</FirstName></Name><UniqueId>123456789A</UniqueId><Email>fred_muggs@bananas.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence></LoggedOnUser><PartnerDetails><CompanyId>18z7gsgn</CompanyId><TradeStyleName>We Have Bananas, Inc</TradeStyleName></PartnerDetails><SignonRequestDetails><Timestamp>2010-01-18 17:18:06 GMT</Timestamp><Expiration>2015-01-18 17:21:06 GMT</Expiration><SessionID>1234ABCD</SessionID></SignonRequestDetails></SignonRequest>';

    $this->assertEquals($expected, $actual);


  }

}