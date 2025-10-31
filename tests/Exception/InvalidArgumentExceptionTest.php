<?php

declare(strict_types=1);

namespace Tourze\TLSSession\Tests\Exception;

use PHPUnit\Framework\Attributes\CoversClass;
use Tourze\PHPUnitBase\AbstractExceptionTestCase;
use Tourze\TLSSession\Exception\InvalidArgumentException;

/**
 * @internal
 */
#[CoversClass(InvalidArgumentException::class)]
final class InvalidArgumentExceptionTest extends AbstractExceptionTestCase
{
    public function testExceptionCanBeCreated(): void
    {
        $exception = new InvalidArgumentException('Test message');

        self::assertSame('Test message', $exception->getMessage());
    }

    public function testExceptionCanBeCreatedWithCode(): void
    {
        $exception = new InvalidArgumentException('Test message', 123);

        self::assertSame(123, $exception->getCode());
    }

    public function testExceptionCanBeCreatedWithPreviousException(): void
    {
        $previous = new \Exception('Previous exception');
        $exception = new InvalidArgumentException('Test message', 0, $previous);

        self::assertSame($previous, $exception->getPrevious());
    }
}
