<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests\KeyDerivation;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\KeyDerivation\SessionKeys;

/**
 * SessionKeys 测试类
 *
 * @internal
 */
#[CoversClass(SessionKeys::class)]
final class SessionKeysTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // SessionKeys 是一个简单的数据对象，直接实例化
    }

    /**
     * 测试构造函数和只读属性访问
     */
    public function testConstructorAndReadonlyProperties(): void
    {
        $clientWriteKey = random_bytes(32);
        $serverWriteKey = random_bytes(32);
        $clientWriteIV = random_bytes(16);
        $serverWriteIV = random_bytes(16);
        $clientMACKey = random_bytes(32);
        $serverMACKey = random_bytes(32);

        $sessionKeys = new SessionKeys(
            $clientWriteKey,
            $serverWriteKey,
            $clientWriteIV,
            $serverWriteIV,
            $clientMACKey,
            $serverMACKey
        );

        $this->assertSame($clientWriteKey, $sessionKeys->clientWriteKey);
        $this->assertSame($serverWriteKey, $sessionKeys->serverWriteKey);
        $this->assertSame($clientWriteIV, $sessionKeys->clientWriteIV);
        $this->assertSame($serverWriteIV, $sessionKeys->serverWriteIV);
        $this->assertSame($clientMACKey, $sessionKeys->clientMACKey);
        $this->assertSame($serverMACKey, $sessionKeys->serverMACKey);
    }

    /**
     * 测试客户端密钥集合
     */
    public function testClientKeys(): void
    {
        $clientWriteKey = random_bytes(32);
        $clientWriteIV = random_bytes(16);
        $clientMACKey = random_bytes(32);

        $sessionKeys = new SessionKeys(
            $clientWriteKey,
            random_bytes(32),
            $clientWriteIV,
            random_bytes(16),
            $clientMACKey,
            random_bytes(32)
        );

        $clientKeys = $sessionKeys->clientKeys();

        $this->assertSame($clientWriteKey, $clientKeys['key']);
        $this->assertSame($clientWriteIV, $clientKeys['iv']);
        $this->assertSame($clientMACKey, $clientKeys['mac_key']);
    }

    /**
     * 测试服务器密钥集合
     */
    public function testServerKeys(): void
    {
        $serverWriteKey = random_bytes(32);
        $serverWriteIV = random_bytes(16);
        $serverMACKey = random_bytes(32);

        $sessionKeys = new SessionKeys(
            random_bytes(32),
            $serverWriteKey,
            random_bytes(16),
            $serverWriteIV,
            random_bytes(32),
            $serverMACKey
        );

        $serverKeys = $sessionKeys->serverKeys();

        $this->assertSame($serverWriteKey, $serverKeys['key']);
        $this->assertSame($serverWriteIV, $serverKeys['iv']);
        $this->assertSame($serverMACKey, $serverKeys['mac_key']);
    }

    /**
     * 测试读取密钥集合（服务器视角）
     */
    public function testReadKeys(): void
    {
        $clientWriteKey = random_bytes(32);
        $clientWriteIV = random_bytes(16);
        $clientMACKey = random_bytes(32);

        $sessionKeys = new SessionKeys(
            $clientWriteKey,
            random_bytes(32),
            $clientWriteIV,
            random_bytes(16),
            $clientMACKey,
            random_bytes(32)
        );

        $readKeys = $sessionKeys->readKeys();

        $this->assertSame($clientWriteKey, $readKeys['key']);
        $this->assertSame($clientWriteIV, $readKeys['iv']);
        $this->assertSame($clientMACKey, $readKeys['mac_key']);
    }

    /**
     * 测试写入密钥集合（服务器视角）
     */
    public function testWriteKeys(): void
    {
        $serverWriteKey = random_bytes(32);
        $serverWriteIV = random_bytes(16);
        $serverMACKey = random_bytes(32);

        $sessionKeys = new SessionKeys(
            random_bytes(32),
            $serverWriteKey,
            random_bytes(16),
            $serverWriteIV,
            random_bytes(32),
            $serverMACKey
        );

        $writeKeys = $sessionKeys->writeKeys();

        $this->assertSame($serverWriteKey, $writeKeys['key']);
        $this->assertSame($serverWriteIV, $writeKeys['iv']);
        $this->assertSame($serverMACKey, $writeKeys['mac_key']);
    }
}
