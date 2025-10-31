<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests;

use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use Tourze\TLSSession\SessionInterface;

/**
 * @internal
 */
#[CoversClass(SessionInterface::class)]
final class SessionInterfaceTest extends TestCase
{
    protected function setUp(): void
    {
        parent::setUp();

        // SessionInterfaceTest 只测试接口定义，不需要设置
    }

    public function testInterfaceDefinesRequiredMethods(): void
    {
        $reflection = new \ReflectionClass(SessionInterface::class);

        // 验证接口定义了所有必需的方法
        self::assertTrue($reflection->hasMethod('getSessionId'));
        self::assertTrue($reflection->hasMethod('setSessionId'));
        self::assertTrue($reflection->hasMethod('getCipherSuite'));
        self::assertTrue($reflection->hasMethod('setCipherSuite'));
        self::assertTrue($reflection->hasMethod('getMasterSecret'));
        self::assertTrue($reflection->hasMethod('setMasterSecret'));
        self::assertTrue($reflection->hasMethod('getCreationTime'));
        self::assertTrue($reflection->hasMethod('setCreationTime'));
        self::assertTrue($reflection->hasMethod('isValid'));
    }

    public function testInterfaceMethodSignatures(): void
    {
        $reflection = new \ReflectionClass(SessionInterface::class);

        // 验证 getSessionId 方法签名
        $method = $reflection->getMethod('getSessionId');
        self::assertSame('string', (string) $method->getReturnType());
        self::assertCount(0, $method->getParameters());

        // 验证 setSessionId 方法签名
        $method = $reflection->getMethod('setSessionId');
        $returnType = $method->getReturnType();
        $this->assertNotNull($returnType, '返回类型不应为null');
        self::assertSame('void', $returnType->__toString());
        $params = $method->getParameters();
        self::assertCount(1, $params);
        self::assertSame('sessionId', $params[0]->getName());
        $paramType = $params[0]->getType();
        $this->assertNotNull($paramType, '参数类型不应为null');
        self::assertSame('string', $paramType->__toString());

        // 验证 isValid 方法签名
        $method = $reflection->getMethod('isValid');
        $returnType = $method->getReturnType();
        $this->assertNotNull($returnType, '返回类型不应为null');
        self::assertSame('bool', $returnType->__toString());
        $params = $method->getParameters();
        self::assertCount(1, $params);
        self::assertSame('currentTime', $params[0]->getName());
        $paramType = $params[0]->getType();
        $this->assertNotNull($paramType, '参数类型不应为null');
        self::assertSame('int', $paramType->__toString());
        self::assertTrue($params[0]->isDefaultValueAvailable());
        self::assertSame(0, $params[0]->getDefaultValue());
    }
}
