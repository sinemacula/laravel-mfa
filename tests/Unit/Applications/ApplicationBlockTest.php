<?php

declare(strict_types = 1);

namespace Tests\Unit\Applications;

use Illuminate\Config\Repository;
use PHPUnit\Framework\Attributes\CoversClass;
use PHPUnit\Framework\TestCase;
use SineMacula\Laravel\Mfa\Applications\ApplicationBlock;

/**
 * Unit tests for `ApplicationBlock`: the raw block it reads for one
 * application, the keys it refuses, its flags and type lists, and the keys it
 * names in its messages.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
#[CoversClass(ApplicationBlock::class)]
final class ApplicationBlockTest extends TestCase
{
    /**
     * The block is read as configured, and is empty for an application with
     * none or when the applications block is not an array.
     *
     * @return void
     */
    public function testReadsTheBlock(): void
    {
        self::assertSame(['types' => ['totp']], self::block(['types' => ['totp']])->all());
        self::assertSame([], (new ApplicationBlock(new Repository, 'web'))->all());
        self::assertSame([], (new ApplicationBlock(new Repository(['mfa' => ['applications' => 'web']]), 'web'))->all());
    }

    /**
     * A key the block does not know is refused, an integer key included, each
     * listed in the message.
     *
     * @return void
     */
    public function testRefusesKeysItDoesNotKnow(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.applications.web holds keys it does not know: 0, recovery.');

        self::block(['types' => [], 0 => 'totp', 'recovery' => true])->all();
    }

    /**
     * A block that is not an array is refused.
     *
     * @return void
     */
    public function testRefusesABlockThatIsNotAnArray(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.applications.web must be an array.');

        self::block('totp')->all();
    }

    /**
     * A nested block is read as configured, empty when it is not set, and
     * refuses a key it does not know, an integer key included.
     *
     * @return void
     */
    public function testReadsANestedBlock(): void
    {
        self::assertSame(['enabled' => true], self::block(['bootstrap' => ['enabled' => true]])->nested('bootstrap'));
        self::assertSame([], self::block([])->nested('limits'));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.applications.web.limits holds keys it does not know: 0.');

        self::block(['limits' => [5]])->nested('limits');
    }

    /**
     * A nested block that is not an array is refused.
     *
     * @return void
     */
    public function testRefusesANestedBlockThatIsNotAnArray(): void
    {
        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.applications.web.bootstrap must be an array.');

        self::block(['bootstrap' => true])->nested('bootstrap');
    }

    /**
     * A flag is off when not set, reads a boolean, and refuses anything else.
     *
     * @return void
     */
    public function testReadsAFlag(): void
    {
        self::assertFalse(self::block([])->isEnabled('bootstrap'));
        self::assertTrue(self::block(['bootstrap' => ['enabled' => true]])->isEnabled('bootstrap'));
        self::assertFalse(self::block(['bootstrap' => ['enabled' => false]])->isEnabled('bootstrap'));

        $this->expectException(\InvalidArgumentException::class);
        $this->expectExceptionMessage('mfa.applications.web.bootstrap.enabled must be true or false.');

        self::block(['bootstrap' => ['enabled' => 'true']])->isEnabled('bootstrap');
    }

    /**
     * A list of distinct type names is read as it is, and anything else is
     * refused under the setting's key.
     *
     * @return void
     */
    public function testReadsATypeList(): void
    {
        $block = self::block([]);

        self::assertSame([], $block->names('types', []));
        self::assertSame(['totp', 'sms'], $block->names('types', ['totp', 'sms']));

        foreach (['totp', ['a' => 'totp'], ['totp', 'totp'], [null], ['']] as $value) {

            try {
                $block->names('bootstrap.types', $value);
                self::fail('Expected the list to be refused.');
            } catch (\InvalidArgumentException $exception) {
                self::assertSame('mfa.applications.web.bootstrap.types must be a list of distinct factor type names.', $exception->getMessage());
            }
        }
    }

    /**
     * The key of the block, and of a setting in it, names the application.
     *
     * @return void
     */
    public function testNamesKeys(): void
    {
        self::assertSame('mfa.applications.web', self::block([])->key());
        self::assertSame('mfa.applications.web.limits.pending', self::block([])->key('limits.pending'));
    }

    /**
     * Build the reader over the `web` application's block.
     *
     * @param  mixed  $block
     * @return \SineMacula\Laravel\Mfa\Applications\ApplicationBlock
     */
    private static function block(mixed $block): ApplicationBlock
    {
        return new ApplicationBlock(new Repository(['mfa' => ['applications' => ['web' => $block]]]), 'web');
    }
}
