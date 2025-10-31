<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSHandshakeNegotiation\Session\PSKHandler;
use Tourze\TLSHandshakeNegotiation\Session\TLS13PSKSession;

/**
 * @internal
 */
#[CoversClass(PSKHandler::class)]
final class PSKHandlerTest extends TestCase
{
    private PSKHandler $pskHandler;

    protected function setUp(): void
    {
        parent::setUp();

        $this->pskHandler = new PSKHandler();
    }

    public function testRegisterPSK(): void
    {
        $identity = 'test-identity';
        $key = random_bytes(32);

        $result = $this->pskHandler->registerPSK($identity, $key);

        $this->assertInstanceOf(PSKHandler::class, $result, 'registerPSK应返回PSKHandler实例');
        $this->assertTrue($this->pskHandler->hasPSK($identity), '注册后PSK应存在');
        $this->assertEquals($key, $this->pskHandler->getPSK($identity), '注册的PSK应可以检索');
    }

    public function testRegisterAndRetrievePSK(): void
    {
        // 测试注册和检索PSK
        $identity = 'test-identity';
        $key = random_bytes(32);

        $this->pskHandler->registerPSK($identity, $key);

        $retrievedKey = $this->pskHandler->getPSK($identity);
        $this->assertEquals($key, $retrievedKey, '检索到的PSK应与注册的相同');
    }

    public function testHasPSK(): void
    {
        $identity = 'test-identity';
        $key = random_bytes(32);

        $this->assertFalse($this->pskHandler->hasPSK($identity), '未注册的PSK身份应返回false');

        $this->pskHandler->registerPSK($identity, $key);
        $this->assertTrue($this->pskHandler->hasPSK($identity), '已注册的PSK身份应返回true');
    }

    public function testRemovePSK(): void
    {
        $identity = 'test-identity';
        $key = random_bytes(32);

        $this->pskHandler->registerPSK($identity, $key);
        $this->assertTrue($this->pskHandler->hasPSK($identity));

        $this->pskHandler->removePSK($identity);
        $this->assertFalse($this->pskHandler->hasPSK($identity), '移除后的PSK不应存在');
    }

    public function testBindSessionToPSK(): void
    {
        $identity = 'test-identity';
        $key = random_bytes(32);

        // 创建一个真实的TLS13PSKSession实例而不是mock
        $session = new TLS13PSKSession(
            bin2hex(random_bytes(16)),
            'test-psk-identity'
        );

        $this->pskHandler->registerPSK($identity, $key);
        $this->pskHandler->bindSessionToPSK($identity, $session);

        $boundSession = $this->pskHandler->getSessionByPSK($identity);
        $this->assertSame($session, $boundSession, '应返回绑定到PSK的会话');
    }

    public function testGetUnboundSession(): void
    {
        $identity = 'test-identity';

        $boundSession = $this->pskHandler->getSessionByPSK($identity);
        $this->assertNull($boundSession, '未绑定的PSK应返回null');
    }
}
