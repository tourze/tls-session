<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\ConcreteTLSSession;
use Tourze\TLSSession\SessionSecurityValidator;
use Tourze\TLSSession\TLS13PSKSession;
use Tourze\TLSSession\TLSSession;

/**
 * @internal
 */
#[CoversClass(SessionSecurityValidator::class)]
final class SessionSecurityValidatorTest extends TestCase
{
    private SessionSecurityValidator $validator;

    protected function setUp(): void
    {
        parent::setUp();

        $this->validator = new SessionSecurityValidator();
    }

    public function testValidateTLS12Session(): void
    {
        // 创建一个TLS 1.2会话
        $session = new ConcreteTLSSession(
            sessionId: random_bytes(32),
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );

        // 验证相同的加密套件和协议版本
        $isValid = $this->validator->validateTLS12Session(
            $session,
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            0x0303
        );

        $this->assertTrue($isValid, '相同加密套件和版本应该验证通过');

        // 验证不同的加密套件应该失败
        $isInvalid = $this->validator->validateTLS12Session(
            $session,
            'TLS_RSA_WITH_AES_256_CBC_SHA',
            0x0303
        );

        $this->assertFalse($isInvalid, '不同加密套件应该验证失败');
    }

    public function testValidatesTLS12SessionWithSameCipherSuite(): void
    {
        // 创建一个TLS 1.2会话
        $session = new ConcreteTLSSession(
            sessionId: random_bytes(32),
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );

        // 验证相同的加密套件和协议版本
        $isValid = $this->validator->validateTLS12Session(
            $session,
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            0x0303
        );

        $this->assertTrue($isValid);
    }

    public function testRejectsTLS12SessionWithDifferentCipherSuite(): void
    {
        // 创建一个TLS 1.2会话
        $session = new ConcreteTLSSession(
            sessionId: random_bytes(32),
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );

        // 验证不同的加密套件
        $isValid = $this->validator->validateTLS12Session(
            $session,
            'TLS_RSA_WITH_AES_256_CBC_SHA',
            0x0303
        );

        $this->assertFalse($isValid);
    }

    public function testRejectsTLS12SessionWithLowerTLSVersion(): void
    {
        // 创建一个TLS 1.2会话
        $session = new ConcreteTLSSession(
            sessionId: random_bytes(32),
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );

        // 尝试用TLS 1.1版本进行验证
        $isValid = $this->validator->validateTLS12Session(
            $session,
            'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            0x0302 // TLS 1.1
        );

        $this->assertFalse($isValid);
    }

    public function testValidateTLS13PSK(): void
    {
        // 创建一个TLS 1.3 PSK会话
        $pskIdentity = random_bytes(16);
        $session = new TLS13PSKSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 0,
            masterSecret: random_bytes(32), // 作为presharedKey使用
            timestamp: time(),
            pskIdentity: bin2hex($pskIdentity),
            ticketAgeAdd: mt_rand(0, 1000000),
            ticketNonce: random_bytes(16),
            resumptionMasterSecret: random_bytes(32)
        );

        // 设置加密套件
        $session->setCipherSuite('TLS_AES_128_GCM_SHA256');

        // 设置早期数据支持（可选）
        $session->setMaxEarlyDataSize(16384);

        // 验证相同的加密套件
        $isValid = $this->validator->validateTLS13PSK(
            $session,
            'TLS_AES_128_GCM_SHA256'
        );

        $this->assertTrue($isValid, '相同加密套件应该验证通过');

        // 验证不同的加密套件应该失败
        $isInvalid = $this->validator->validateTLS13PSK(
            $session,
            'TLS_AES_256_GCM_SHA384'
        );

        $this->assertFalse($isInvalid, '不同加密套件应该验证失败');
    }

    public function testValidatesTLS13PSKWithSameCipherSuite(): void
    {
        // 创建一个TLS 1.3 PSK会话
        $pskIdentity = random_bytes(16);
        $session = new TLS13PSKSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 0,
            masterSecret: random_bytes(32), // 作为presharedKey使用
            timestamp: time(),
            pskIdentity: bin2hex($pskIdentity),
            ticketAgeAdd: mt_rand(0, 1000000),
            ticketNonce: random_bytes(16),
            resumptionMasterSecret: random_bytes(32)
        );

        // 设置加密套件
        $session->setCipherSuite('TLS_AES_128_GCM_SHA256');

        // 设置早期数据支持（可选）
        $session->setMaxEarlyDataSize(16384);

        // 验证相同的加密套件
        $isValid = $this->validator->validateTLS13PSK(
            $session,
            'TLS_AES_128_GCM_SHA256'
        );

        $this->assertTrue($isValid);
    }

    public function testRejectsTLS13PSKWithDifferentCipherSuite(): void
    {
        // 创建一个TLS 1.3 PSK会话
        $pskIdentity = random_bytes(16);
        $session = new TLS13PSKSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 0,
            masterSecret: random_bytes(32), // 作为presharedKey使用
            timestamp: time(),
            pskIdentity: bin2hex($pskIdentity),
            ticketAgeAdd: mt_rand(0, 1000000),
            ticketNonce: random_bytes(16),
            resumptionMasterSecret: random_bytes(32)
        );

        // 设置加密套件
        $session->setCipherSuite('TLS_AES_128_GCM_SHA256');

        // 设置早期数据支持（可选）
        $session->setMaxEarlyDataSize(16384);

        // 验证不同的加密套件
        $isValid = $this->validator->validateTLS13PSK(
            $session,
            'TLS_AES_256_GCM_SHA384'
        );

        $this->assertFalse($isValid);
    }

    public function testFuzzyTLS13PSKMatching(): void
    {
        // 创建一个TLS 1.3 PSK会话
        $pskIdentity = random_bytes(16);
        $session = new TLS13PSKSession(
            sessionId: bin2hex(random_bytes(16)),
            cipherSuite: 0,
            masterSecret: random_bytes(32), // 作为presharedKey使用
            timestamp: time(),
            pskIdentity: bin2hex($pskIdentity),
            ticketAgeAdd: mt_rand(0, 1000000),
            ticketNonce: random_bytes(16),
            resumptionMasterSecret: random_bytes(32)
        );

        // 设置加密套件
        $session->setCipherSuite('TLS_AES_128_GCM_SHA256');

        // 设置早期数据支持（可选）
        $session->setMaxEarlyDataSize(16384);

        // 测试不区分大小写的匹配
        $isValid = $this->validator->validateTLS13PSK(
            $session,
            'tls_aes_128_gcm_sha256', // 小写格式
            true // 启用模糊匹配
        );

        $this->assertTrue($isValid);
    }

    public function testValidateSessionAgainstServerOptions(): void
    {
        // 创建一个TLS 1.2会话
        $session = new ConcreteTLSSession(
            sessionId: random_bytes(32),
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );

        // 创建服务器配置选项
        $serverOptions = [
            'allowDowngrade' => false,
            'requireExactMatch' => true,
            'minimumTlsVersion' => 0x0303,
            'allowedCipherSuites' => [
                'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            ],
        ];

        // 验证会话是否符合服务器配置
        $isValid = $this->validator->validateSessionAgainstServerOptions(
            $session,
            $serverOptions
        );

        $this->assertTrue($isValid, '符合服务器配置的会话应该验证通过');

        // 测试不在允许列表中的加密套件
        $serverOptionsRestricted = [
            'allowDowngrade' => false,
            'requireExactMatch' => true,
            'minimumTlsVersion' => 0x0303,
            'allowedCipherSuites' => [
                'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            ],
        ];

        $isInvalid = $this->validator->validateSessionAgainstServerOptions(
            $session,
            $serverOptionsRestricted
        );

        $this->assertFalse($isInvalid, '不符合服务器配置的会话应该验证失败');
    }

    public function testExtendedValidationWithServerOptions(): void
    {
        // 创建一个TLS 1.2会话
        $session = new ConcreteTLSSession(
            sessionId: random_bytes(32),
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );

        // 创建服务器配置选项
        $serverOptions = [
            'allowDowngrade' => false,
            'requireExactMatch' => true,
            'minimumTlsVersion' => 0x0303,
            'allowedCipherSuites' => [
                'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            ],
        ];

        // 验证会话是否符合服务器配置
        $isValid = $this->validator->validateSessionAgainstServerOptions(
            $session,
            $serverOptions
        );

        $this->assertTrue($isValid);
    }

    public function testRejectsSessionNotInAllowedCipherSuites(): void
    {
        // 创建一个TLS 1.2会话
        $session = new ConcreteTLSSession(
            sessionId: random_bytes(32),
            masterSecret: random_bytes(48),
            cipherSuite: 'TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA',
            tlsVersion: 0x0303, // TLS 1.2
            timestamp: time()
        );

        // 创建服务器配置选项
        $serverOptions = [
            'allowDowngrade' => false,
            'requireExactMatch' => true,
            'minimumTlsVersion' => 0x0303,
            'allowedCipherSuites' => [
                'TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256',
                'TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384',
            ],
        ];

        // 验证会话是否符合服务器配置
        $isValid = $this->validator->validateSessionAgainstServerOptions(
            $session,
            $serverOptions
        );

        $this->assertFalse($isValid);
    }
}
