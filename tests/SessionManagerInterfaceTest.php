<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\SessionInterface;
use Tourze\TLSSession\SessionManagerInterface;

/**
 * @internal
 */
#[CoversClass(SessionManagerInterface::class)]
final class SessionManagerInterfaceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // SessionManagerInterfaceTest 只测试接口定义，不需要设置
    }

    public function testInterfaceDefinesRequiredMethods(): void
    {
        $reflection = new \ReflectionClass(SessionManagerInterface::class);

        // 验证接口定义了所有必需的方法
        self::assertTrue($reflection->hasMethod('createSession'));
        self::assertTrue($reflection->hasMethod('getSessionById'));
        self::assertTrue($reflection->hasMethod('storeSession'));
        self::assertTrue($reflection->hasMethod('removeSession'));
        self::assertTrue($reflection->hasMethod('cleanExpiredSessions'));
    }

    public function testCreateSessionMethodSignature(): void
    {
        $reflection = new \ReflectionClass(SessionManagerInterface::class);
        $method = $reflection->getMethod('createSession');

        $returnType = $method->getReturnType();
        $this->assertNotNull($returnType, '返回类型不应为null');
        self::assertSame(SessionInterface::class, $returnType->__toString());

        $params = $method->getParameters();
        self::assertCount(2, $params);
        self::assertSame('cipherSuite', $params[0]->getName());
        $paramType0 = $params[0]->getType();
        $this->assertNotNull($paramType0, '参数类型不应为null');
        self::assertSame('string', $paramType0->__toString());
        self::assertSame('masterSecret', $params[1]->getName());
        $paramType1 = $params[1]->getType();
        $this->assertNotNull($paramType1, '参数类型不应为null');
        self::assertSame('string', $paramType1->__toString());
    }

    public function testGetSessionByIdMethodSignature(): void
    {
        $reflection = new \ReflectionClass(SessionManagerInterface::class);
        $method = $reflection->getMethod('getSessionById');

        $returnType = $method->getReturnType();
        $this->assertNotNull($returnType, '返回类型不应为null');
        self::assertTrue($returnType->allowsNull());
        self::assertSame('?' . SessionInterface::class, $returnType->__toString());

        $params = $method->getParameters();
        self::assertCount(1, $params);
        self::assertSame('sessionId', $params[0]->getName());
        $paramType = $params[0]->getType();
        $this->assertNotNull($paramType, '参数类型不应为null');
        self::assertSame('string', $paramType->__toString());
    }

    public function testStoreSessionMethodSignature(): void
    {
        $reflection = new \ReflectionClass(SessionManagerInterface::class);
        $method = $reflection->getMethod('storeSession');

        $returnType = $method->getReturnType();
        $this->assertNotNull($returnType, '返回类型不应为null');
        self::assertSame('bool', $returnType->__toString());

        $params = $method->getParameters();
        self::assertCount(1, $params);
        self::assertSame('session', $params[0]->getName());
        $paramType = $params[0]->getType();
        $this->assertNotNull($paramType, '参数类型不应为null');
        self::assertSame(SessionInterface::class, $paramType->__toString());
    }

    public function testRemoveSessionMethodSignature(): void
    {
        $reflection = new \ReflectionClass(SessionManagerInterface::class);
        $method = $reflection->getMethod('removeSession');

        $returnType = $method->getReturnType();
        $this->assertNotNull($returnType, '返回类型不应为null');
        self::assertSame('bool', $returnType->__toString());

        $params = $method->getParameters();
        self::assertCount(1, $params);
        self::assertSame('sessionId', $params[0]->getName());
        $paramType = $params[0]->getType();
        $this->assertNotNull($paramType, '参数类型不应为null');
        self::assertSame('string', $paramType->__toString());
    }

    public function testCleanExpiredSessionsMethodSignature(): void
    {
        $reflection = new \ReflectionClass(SessionManagerInterface::class);
        $method = $reflection->getMethod('cleanExpiredSessions');

        $returnType = $method->getReturnType();
        $this->assertNotNull($returnType, '返回类型不应为null');
        self::assertSame('int', $returnType->__toString());
        self::assertCount(0, $method->getParameters());
    }
}
