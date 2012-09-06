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
class IbmPwSecIntegrationTest extends PHPUnit_Framework_TestCase {
  
  public function  setUp() {

    parent::setUp();

    $this->exceptionLogFile = tempnam(sys_get_temp_dir(), 'exception_log_file');

    $Logger = Log::factory('file', $this->exceptionLogFile);

    IbmPwSecException::setLogger($Logger);

    $this->signatureCacheFile = tempnam(sys_get_temp_dir(), 'signature_cache_file');

    $SignatureCache = new IbmPwSec_SignatureCache_File(array('path' => $this->signatureCacheFile));

    $password = 'Fun2Plan10';

    $Decryptor = new IbmPwSec_Decryptor_Aes($password);

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

    $vendorCode = 'ibm_pw_bpp';

    $this->IbmPwSec = new IbmPwSec($SignatureCache, $Decryptor, $certificate, $vendorCode);

  }

  public function testValidRequest() {

    $message = 'AAAAELS0dxyK8JrYnVGK1QvYqIiAbsz6g3h%2FAa8MVGSJDL%2FFFyoYqNyjwYnp8xbhRaeGYXyqlMQ5%2FQxYox%2Fg5RFBmJBhHrKVdJaLUwLBhsFTqeT11A1VbuuZ9SmWpX25YFiTxytz%2F0KLLnPAWXpRKjA%2FWpkAt6qzQa64L7tQ7rZQzeGE8GvvVDCXczi2tBps5JH7eSHy0XvdWlIsZIqk3hfjOaU97i9iy3ZV%2Fek%2BqdbWermKAUuWzXgLoY4CuERhlol07BWan1QdkZRNsNvdId%2Bbr43MSzwdsYYmBOIf6ox2EjHcvuYo48rOPh%2FFG6LPd7gjHmG%2FihsqSu1ThhQTQZ04Mj0mJ968BNxNn%2F7dsEreYlWJtytQs%2FVXmhVTG8tpEGmtzb6I%2BJeEv3AMQAR8Vs63NG5WRcmuwQZjhb%2BDQDgceNQcf7Dt%2Fz6UbKh%2FMlJQAJ18JgoNu0Xn6n0OJMQKAGxE8fmyaVYfeZmFBvGb3oa9m0wFNykEv4qojj3Wwq%2FTENUcAA8RPz6ZyOGwP8HSKf41UPeuzcsS6t0rRVmF72Js3HQj2K0jekp6hLyYwP03uUnJdw%3D%3D';
    $signature = 'IraMFD4lNVUpepemRlXONqsC8MCrfS1ONa44G5t%2FBLwf8kNT4lB0eySdcNnSJNIR1vICnhT8NRCGZWPvOtxMF5tWFy95f5o9B3J34YfkH5uAckkcjrsZlOZ7RIdJw3HaBnv1ghVzwXv09yvbws6QStY36gUtTUsZlEEcrkOgPtA%3D';
    $expected = '<SignonRequest vendor="ibm_pw_bpp"><LoggedOnUser><Name><PrimeSurname>Case1</PrimeSurname><FirstName>Test</FirstName></Name><UniqueId>T000000101</UniqueId><Email>testcase1@nowhere.com</Email><CountryOfResidence>us</CountryOfResidence><PreferredLanguageCode>en</PreferredLanguageCode><IsIBMContact>No</IsIBMContact></LoggedOnUser><PartnerDetails><CompanyId>1</CompanyId><TradeStyleName>Pitney Bowes Defined Partner 1</TradeStyleName><PartnerLevel>Member</PartnerLevel><CountryEnterpriseAddress><CountryCode>US</CountryCode></CountryEnterpriseAddress></PartnerDetails><SignonRequestDetails><Timestamp>2010-11-19 21:54:34 GMT</Timestamp><Expiration>2015-11-19 21:57:34 GMT</Expiration><SessionID>jh0GbUNIoVLbLrlJxpE3cHD</SessionID></SignonRequestDetails></SignonRequest>';

    $actual = $this->IbmPwSec->getMessage(urldecode($message), urldecode($signature), true);

    $this->assertEquals($expected, $actual);
    
  }

//  public function testInvalidSignature() {
//
//    $message = urldecode('AAAACEvCkU2AqOyrVmQklHWus741kvMTfMFMizhOCuosJFb88m3NWmZb%2BOXjxvDLGwVbTd8TpFRvN8Hw3qUEB5%2FV0K%2BcnrbynUxYNm7MMeBOTjNPNOWm65s1VMtE74aJrAuM3D08kpIxhPibf59nctY2XDA8Ivysj4NcsrIKYnbPJTEv9DYsU9KFuoTSXO7yCNkKFJVGilkidhBv6B2o%2BWEaISGuSUhrGqDB8W%2BMrQFJnIGhgPhkgrGkPM4jAPTHR4gTZBqnmcfCgTD%2Bj%2FyAbslje6Lx8I8OwMA%2BIrNeHubbayYZkVB8QsAqUQaILwvlCEndXGIG6AYTY6lzOlQguYS6HdiabP34iDqT63pKhHxKZ4Wrva7%2FkvGqH3eUMlm1SwRYBj8Fxjc2yhBsKM41V1PQLLybYTouEVSKUysIfa23US2gp7BbMOGD4G5cvz7%2FSICvbfoou338gcf%2FKQNXU8jTEgZ50PqLHf8%2FWkq7WGjYTzKDlUSwaB2vyNfgceMQ4T1iMbGYJXD4LldM9B2VvkFmBMb0McKuj%2B%2Ft4h%2BOVKUxA%2FtvnejT6I8%2F80yBfJT3ddx5sdyuVzBqSJgpT28MzlyfiW0mb%2Ff4aHLZPliiTqA%2BXsf8hGBVeh616Q%2Bx2O5OnuN0wnFX5lQ07U7A%2BtOAsRxGXl6NVuQqlNH1xxo1fG4bPe9O6a25idZF91Jy686in2iKsheT5DUCrQKK%2BkENscxbn7u6h11KeN9qndBEc0ptOWIbhrk5CKUApPvHJKWHndE%2Fc1n%2Fqyk0jmP9z0Qsx7oATDjFBfnCwBkHBUIxotxvi7NqMRPKOHbLzBJCr%2F33GVYEcUlCuUWWUTB6Of70XvP%2FXOwZoDgGVc84KINVrN%2BpikP1');
//    $signature = urldecode('LMCABffONRtc2by7XXvYtY1I%2BpxM2yZ40m1CK0W2cnboqEYSLGqglJev6AV6cg4MungY3Ic0qpe7AqEjwKyt3wxLoWsETddRg2Pka%2FygVCGn3mhOdjb3XljYeCFD4%2Bq2ipfQ7BZhwNaOGb3%2F2QGjwrfqLL3zfrp%2Bgqpg7x1raZI%3D');
//
//    try {
//      $this->IbmPwSec->getMessage($message, $signature);
//    } catch (IbmPwSecException $expected) {
//      $handle = fopen($this->signatureCacheFile, 'r');
//      list($timestamp, $expectedSignature) = fgetcsv($handle, null, ' ');
//      fclose($handle);
//      $this->assertStringMatchesFormat('%d', $timestamp);
//      $this->assertEquals($expectedSignature, $signature);
//      $handle = fopen($this->exceptionLogFile, 'r');
//      $line = fgets($handle);
//      fclose($handle);
//      $this->assertRegExp('/Invalid Signature\s*$/', $line);
//      return;
//    }
//
//    $this->fail('IbmPwSecException with message "Invalid Signature" was not thrown');
//
//  }
//
//  public function testMessageDecryption() {
//
//    $message = urldecode('AAAACGbYj6MlopWx3ZHf%2FrGCkZyNCZKdG%2FMgeok5Fwbp11dXeGAn6KlYEURFjLt2vdYnSBhsWROP9dbeKy2kAOIAATehNvo1X92x%2FbUwurne%2Fr%2FWF0g7%2FN4w%2B4HKKzLxXQw8hN3L9wUGCxxHE6thHXGdwRtSbculYhfiBcFzGG%2B03sLNAs5Q%2BBcsssQGywvHLIQk%2FGhizwNjWfgbGYbIzxQyQ%2FE8nDWMKJveiYUKJKifxnfOQVdVhfSjPcji%2BJ%2FhlIQQ3HyEfIQRmWmtXGc45wUcuLgSXNsgXW%2BjQnjpeDvgA2mjwXhbA0DCca3sUJvAL7XtTrGbH%2BGwMh%2BDVr1N4zkANM0PNwvLHpH4Ogz6sdpjRxN3ynMJ%2F2a2AoGv1Gz%2Fg3U7z%2FCc3QfdpymzBTHZTccMucisQA1HNmEcxhU%2BeGwfWY95Y3N2HzMHHQjDwg%2BUosmzgleVUIXzMgkFeEp42ZmHEWs6ft2SKLRHlAbiFpbCwevtxU9sTVpgjj1XWtsZETtS6QRYyt8UqLJEoNBhR%2Ft0oTSs9QPRNTX0%2BwuRQx0B7HAZRJZFHkZTDZrLTv4Cr3E7lELppnRnO%2FpMCYsb80oVADe4n8U4Mg0h7pqF2j%2FAU41pMw75b5ZCWBAh6sPpNC8AfHeQdwZkXb0VpwVAaO%2FgE8V7Ja39w9ziOkFqVFoipCrxLaU6dXh4c%2BcT5nY%2FoKzCpJWEbzGaWjuiqy1i3M1PUUIt%2FGi9XLkhR%2FCjtWqRkmONk4Qy87YesNghIPYRjlpP%2F2vm6IegGXNlhlDwS4BS4LOu4%2BHUMECCJ%2B40lyaf6DFcTR7OuJE4HeMNUqrIwXJK7Ilv34s8icKWEiNopjsYuX%2F6LdnQzIQQ21UaSTNbFxRR');
//    $signature = 'YGkeD1i%2Bs96cyzJQ7DIFxKKzsFhQ6xCin4g4P5wmUs3WYnBqOBbg3hFmdZ9%2BFnqcvFetSYd5jmPxHknbfcHX2nmu8TO6dnXxPOMZNqTGdMUalhM3WTcoClGcu2jGCOxaMXMO20bjfNfldI9%2FbKFrxbmAIFEGhHDfbELRX0cjg2g%3D';
//    $signature = urldecode($signature);
//
//    try {
//      $this->IbmPwSec->getMessage($message, $signature);
//    } catch (IbmPwSecException $expected) {
//      $handle = fopen($this->signatureCacheFile, 'r');
//      list($timestamp, $expectedSignature) = fgetcsv($handle, null, ' ');
//      fclose($handle);
//      $this->assertStringMatchesFormat('%d', $timestamp);
//      $this->assertEquals($expectedSignature, $signature);
//      $handle = fopen($this->exceptionLogFile, 'r');
//      $line = fgets($handle);
//      fclose($handle);
//      $this->assertRegExp('/Could Not Decrypt Message\s*$/', $line);
//      return;
//    }
//
//    $this->fail('IbmPwSecException with message "Could Not Decrypt Message" was not thrown');
//
//  }
//
//  public function testInvalidVendorCode() {
//
//    $message = 'AAAACHFFY39MUlWLWZoveqsOkCwkqpjXPylUOPlgUTdV4coUaO58VjdsIdRFU7NdSyFLCJkr91EIXA1tkdx9%2FBvHGvdls1xVqJODHpBEp8gmcEUdAP%2FhQBoZoh9ZY6WAoAhGdjNoi2C1mRzW2XiksrH8qAJdCCzqiTE%2FFRbCiTCTTGGR6ojFQbTV%2B%2FxnV2XENy%2FLwN4Vm%2BXLFXSz6lsX%2BwRHI5DRPRIJ%2F7t2ylIWF4qoFjPJgO8HFrQ9MEJ0BpElnwJAjQb9UVyyS9Ublyon8wHkolxX8inyHauIhd4UmcWnZOMgdUDBpbjrjSRMKDjRK%2BfGDUxlr8HE68efodt83uyOP%2B9sZkBdDG69dyzp4%2F1UJ7F%2B9jBDoCLXc5EuTXSDIbAMZ0qt7uFqqJLHtqFdHkqjtAMeYB3WwECWjn16VVLH%2BccKNFbFLjoKgc7P0Xra%2FS23jO7VoBHUCRbX%2B1SbTn%2BNlf8Yhjqn9jZN%2FHyupV%2B9ngBa1oumxtoY%2FRklwCC4FTf6cNoIEgoLaA%2F8F73DcjTkvixvlbdcHI4BjqKvkOtUjPVLB7ctXaEZACAOA0THHahjfF3xAyBqEZMCqVIOHdqv2KbRUJfZwKQcsI73mZ%2BEjpOaMeOWK%2FgBFnaUcMLCl%2BD5YfGYv3OMIMS7Jx08lEdTJF%2F58JgvEWFNHdFtqUlapMQYFmx33u9J3eBtO%2FoIbsCQ1BOCZOhpkni4HwZ%2FqbOgcEmMMudQSkFeqFW6Kqq1Vf%2FZie1KKw%2F1yYSdhGinScEemwEjCjUlHkXoDZ87RW4t%2Fd12%2FQZ4E89CLri0D2l7yK7Aq%2BAeUI5ypRCxvncsVkfHsQUJCHkN9pFBJ4QQGr4vrAlqvHhQGD4PA0Tkz%2BK83%2Bz4e%2BoCBXK%2BF5k%3D';
//    $signature = 'jYfMVXhuCaow121tjZZ%2BiU%2FQT2VvNWLey5RbEQZ%2FXytDRvvySPl%2BEXPH9WvU4uJPns6gtF0on90LB%2BXiT8mqw%2BCENx5y%2BjqTBrhygLoEv5NeQ0nxXZ2Hi%2B8gH8nFC6M4%2BVbLd%2Bm%2FpBaE2AzizYwzmV%2FQnd%2BwC4nxFnu7APpVe6c%3D';
//
//    try {
//      $this->IbmPwSec->getMessage($message, $signature);
//    } catch (IbmPwSecException $expected) {
//      $handle = fopen($this->signatureCacheFile, 'r');
//      list($timestamp, $expectedSignature) = fgetcsv($handle, null, ' ');
//      fclose($handle);
//      $this->assertStringMatchesFormat('%d', $timestamp);
//      $this->assertEquals($expectedSignature, $signature);
//      $handle = fopen($this->exceptionLogFile, 'r');
//      $line = fgets($handle);
//      fclose($handle);
//      $this->assertRegExp('/Invalid Vendor Code\s*$/', $line);
//      return;
//    }
//
//    $this->fail('IbmPwSecException with message "Could Not Decrypt Message" was not thrown');
//
//  }
//
//  public function testInvalidCreationTimestamp() {
//
//    $message = 'AAAACCEw8lW8zBUOi%2FOJW1Jp3pULRsa14%2F%2BIOAFFDhU0hzl7F6I%2BzCZPTZWLn8Wzp%2F%2FHq279JTvKL8gAo99LevQGBUyFD3WO48ZViaCAoioqKMBoTUTTUgbcqm1dgtrNhRlTBcupCGeYZDpBM1ke2lztA8PkX%2F%2Fa%2Bp2%2FTmEbIokD55g2YBpDeQqkx9cfygRU01FwTrQLrZygJTyD2WxrqN6eogpXJ5zbVonHVhUtLISdNdDVq0Avl0I2F3Dv7wr5cyL1zoql%2BxH2hqnE%2FFdYmhrQGvwlZE3zCgI0GGbXLsI%2B%2BHKGRdvnYy0JLLcYBSR15qq%2BG%2BTzbyo39ZMfryqKDxh2P0xKnXozBVflzGFCkyGGPVMV4ruImhiMIqAtziaNhyXTHxr4N02zu5ODNWhaqRnNaZRWedvHvc9ONiO4Bfg5y8rwdiaX0J0dyU2BLje%2BDvbIRZwMn12cN%2BXNwHRu5cJuWA0uluUs3DI6g5QfWpWn2a4f5cYQG%2BFQcJtnhCDZ4bFCVN58AQEhI%2BnuXh9yyloWMn9fPIESPyn8LZWDltDkmezeTFEA0HiQ8JMhgYoPxxQ%2FxOcatHZkHCfwOpyyr2vaI1fEDiZ4j%2FlMlWpsJ2EmVF3z%2B0xYwseyqrWB8ZzxeLc3ohwsMz3zwgnUxSdrDHn%2BuqwO2tjXPDHP49HhPu9eySTq0yiUlCpMRLby%2BO0lzUT9Icl6ji65IsreTouO%2BEkD0xSGo5%2FBYyZq%2FV%2FSEr3xI9k97gffIcn%2Bizjq6DmyVSiov%2FsQzOaxEddehHLuI3uqOh7YGTA9zAYdV8P6vyJbyfddDSMwkEkomKGhO1gnbCYBD6y8%2BMvMUo6dtkqmrcbNLzUfinAJNn3vjxbHbmIM1V%2BC';
//    $signature = 'iOQyV8%2BmY5MboBgx81%2F5wRDwC7%2Bn8EPLzS4%2FjJ0UibIHtD28pvJKzJlDg%2BxXkxPjyw6hwFbKXtfuf4c66VZw9SNONJ7TGScUb%2Fao6KpTD52zGWti6f7ZT4%2F2gxEyIlMlWQlpMLLnSFkNXidSUPWaseXfue7yOgN8D%2FkxUgYQq3Y%3D';
//
//    try {
//      $this->IbmPwSec->getMessage($message, $signature);
//    } catch (IbmPwSecException $expected) {
//      $handle = fopen($this->signatureCacheFile, 'r');
//      list($timestamp, $expectedSignature) = fgetcsv($handle, null, ' ');
//      fclose($handle);
//      $this->assertStringMatchesFormat('%d', $timestamp);
//      $this->assertEquals($expectedSignature, $signature);
//      $handle = fopen($this->exceptionLogFile, 'r');
//      $line = fgets($handle);
//      fclose($handle);
//      $this->assertRegExp('/Invalid Timestamp\s*$/', $line);
//      return;
//    }
//
//    $this->fail('IbmPwSecException with message "Could Not Decrypt Message" was not thrown');
//
//  }
//
//  public function testInvalidExpirationTimestamp() {
//
//    $message = 'AAAACPbinBbFZaDBHJPW3eShGAzpMaAFrFUhrMre2e53xEzXW5V4IzK1URlOBQ2iWm88Uef4Aord08fw6XR3w83XLttJZ86u0TYiTr4xrjUCGW2A8xIDC5aRbSSNPlEHLiT0Zsu%2FLet3pu6PGuxVQxUOfBGhT%2FwzqjjG%2BF3Q%2BgFqeN8C%2FAI9hoDQGpCfFr9ISEkoAZZv5cK6wQ%2FA5ZL7kKlBjrSRhjz0d3b5dfg6SZkj%2F8PUDJuKq7n0asZGCvUOVlYm8Gjx2%2BIMzXsO3mp6hc9Fc7PpwpCAZ564FbLSuu0jUdNw1FRtnYruV9luzeo87vOMWmwtlmXqwovnnWaUVGkxpt%2F4phIq%2FAOdMElhn0Fia3buClHBuM30DJslCvw5DAb4PP7OyND2zllJ7n9ordnqgxkNZRrJBhlAuOwz7Vp3q75tKLPY4N3BnzqH3zvDjutvF0qecPW0%2Bj9x6fy%2BUY19uJcofbaMlc2fvX7g%2B%2FYqIaECaZqOTWOTcbZiJe6LJYC8CiLhyU4r41TaP2Xbdm22yMKng0%2FGCf2attFwVNexMtMkiMgNHliEt1Cb6qKYdmdGJCPu6s8AJQVcVOMDFW5EJR13X6Ck%2Fmx9%2FoaVtT%2BiETdcvG4uCezSWN2Yq953ZDr7E1f5Z4sziiy9fEJ1riGRv%2FVhREuSmglgibmPgaA7s9DEaEQaNBcvtX9aqGDGSRo96ta%2F7nhnvwBlA%2BmK7nKfDxpfr0AdbKOJjrdqRncC1hJylsEShDuO%2FlsEmBUtmdQpAK0X5EkGNP5rt5R%2FGw1LuL0OH%2BFe0HKnzBIMOJBheqC9azVKkQfKNklPD0SaZoPww6OXeYvGbujtGVxCE%2BKI6edIUkLu4vfBK2ccm4yhSQh1';
//    $signature = 'YzROkW7sX5X64xPm2E7bC1mMJMP5iLASjblPuRHiLYLhsq25LgPhvc1G%2BvG666RDi6%2BUhbxSBhL8CC2KSTxopI2T1QsShTvkpezuAw6Hss2VXOWbWwaYDb9DFEAVfoODoFxHok0tygbmkchry8SowJ8Llp28F1XLlk8GMUDRQQE%3D';
//
//    try {
//      $this->IbmPwSec->getMessage($message, $signature);
//    } catch (IbmPwSecException $expected) {
//      $handle = fopen($this->signatureCacheFile, 'r');
//      list($timestamp, $expectedSignature) = fgetcsv($handle, null, ' ');
//      fclose($handle);
//      $this->assertStringMatchesFormat('%d', $timestamp);
//      $this->assertEquals($expectedSignature, $signature);
//      $handle = fopen($this->exceptionLogFile, 'r');
//      $line = fgets($handle);
//      fclose($handle);
//      $this->assertRegExp('/Invalid Expiration\s*$/', $line);
//      return;
//    }
//
//    $this->fail('IbmPwSecException with message "Invalid Expiration" was not thrown');
//
//  }
//
//  public function testDuplicateSignature() {
//
//    $message = 'AAAACFalpa6vSxqbwnu5e%2FejmT9i8td9mQdqzViKMZ2KQMSHJb2DPcv7vmXb9jZqK9AUSQj516j%2FwUY7aKUwZ9UqHUJHnFU0PcpUcQIJMW2fMiJ96KFFArzfj9ZSruRnc0LEYgqupKCibmA9xrYHCvYT%2BgzSG30ueun0iqg38uvhLa6m1twc1g3v7cO681nbGJbPZWAusLygjz8oQqhf13vx9hW%2BD0khZHXWwXcHPvZSDc7QwAtn9dbuj3OKBWnSyfvEdwZHjr9osfEe3k8XCp4VImAA9CFR41E3%2BAocT8zqbKSGgRDWCncKv3jdNzJrV8cRtwDVbw3%2B6XxHQ6wpWyGmgkRWg1OIh5VagGe%2BW0kZCsa6p4dHUGIgGA9W1TQltRvMm3dvQRBiXAs6o%2FUfbhwltOTHlkwxnFQLg7h4%2B745O9vzopq1jgObJse5lbG8LILwqs5bEZ7KREBFwT5OuAIzPLfmKqkJyY36VtQ8uEWXyXZ5vJs68Qp1jMBDR%2BoAVgUDNqKZJPDOh7yNrm%2BuJo%2BoXSqE7%2BhJ%2BQNaWYbnbeWX6PqYwMjFyA5e0cWxeg%2BO9waMLHEDzOUPTp5i9chYrIR5NPopGDlhysc3%2FccG%2FXPTCnBnBsLpkBNKD9mmFTohpE%2B8hZoENwkjEA%2FhttZ1ZVsTE41fKkLK4rmWRYhdW29VQCexPNbNOw9MK8h2pJ5gvYYE%2FnjeKKL9d1a7MfZoD%2FWjclNb%2BrRP%2BiCSs8UD0VRNicIj1sYUutgcR9Mqcg%2BMnZiMYmDB5MEUr2Ko1ne6tB5Mm%2BPKuTpHB0D2xLcblHrsvKpoBXq4ZbRcv4OC7SDR0HMulacsz7m3EeJp4HWkkKeOfFoh6Ni2ucWBRtBcgG8EftNE';
//    $signature = 'kg7nPJVhNgcyqS4AwBw7qBUAC8n6nOh0v%2FQq4zxpsf5UwHIlj%2BAGgIUrA232I3PkM1scBAiQsKJ%2BYcBDjxhgn7tnMD26RXQAtpqCR8ra0AnsX2Ch0V9Fbdp68KyoZYauuqWC9pusKJ76M0wiIrKtf8ugJhtqDwYryfxUbtDyqDo%3D';
//
//    $actual = $this->IbmPwSec->getMessage($message, $signature);
//    $expected = '<SignonRequest vendor="ibm_pw_vendorcode"><LoggedOnUser><Name><PrimeSurname>Case 7</PrimeSurname><FirstName>Test</FirstName></Name><UniqueId>T000000107</UniqueId><Email>testcase7@nowhere.com</Email><Telephone>1-800-555-1212</Telephone><CountryOfResidence>US</CountryOfResidence><PreferredLanguageCode>en</PreferredLanguageCode></LoggedOnUser><PartnerDetails><CompanyId>1</CompanyId><TradeStyleName>Test Case 7</TradeStyleName></PartnerDetails><SignonRequestDetails><Timestamp>2010-08-13 15:13:09 GMT</Timestamp><Expiration>2015-08-13 15:16:09 GMT</Expiration><SessionID>4Ds_bkJBukb9sC8W0PhcSBx</SessionID></SignonRequestDetails></SignonRequest>';
//
//    $this->assertEquals($expected, $actual);
//
//    try {
//      $this->IbmPwSec->getMessage($message, $signature);
//    } catch (IbmPwSecException $expected) {
//      $handle = fopen($this->signatureCacheFile, 'r');
//      list($timestamp, $expectedSignature) = fgetcsv($handle, null, ' ');
//      fclose($handle);
//      $this->assertStringMatchesFormat('%d', $timestamp);
//      $this->assertEquals($expectedSignature, $signature);
//      $handle = fopen($this->exceptionLogFile, 'r');
//      $line = fgets($handle);
//      fclose($handle);
//      $this->assertRegExp('/Duplicate Signature\s*$/', $line);
//      return;
//    }
//
//    $this->fail('IbmPwSecException with message "Duplicate Signature" was not thrown');
//
//  }
  
  public function  tearDown() {
    @unlink($this->signatureCacheFile);
    @unlink($this->exceptionLogFile);
    parent::tearDown();
  }

}