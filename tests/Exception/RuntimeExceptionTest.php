<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSSession\Exception\RuntimeException;

/**
 * @internal
 */
#[CoversClass(RuntimeException::class)]
final class RuntimeExceptionTest extends AbstractExceptionTestCase
{
    public function testExceptionCanBeCreated(): void
    {
        $exception = new RuntimeException('Test message');

        self::assertSame('Test message', $exception->getMessage());
    }

    public function testExceptionCanBeCreatedWithCode(): void
    {
        $exception = new RuntimeException('Test message', 456);

        self::assertSame(456, $exception->getCode());
    }

    public function testExceptionCanBeCreatedWithPreviousException(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = new RuntimeException('Test message', 0, $previous);

        self::assertSame($previous, $exception->getPrevious());
    }
}
