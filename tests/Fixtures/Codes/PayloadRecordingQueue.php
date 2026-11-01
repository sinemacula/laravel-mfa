<?php

declare(strict_types = 1);

namespace Tests\Fixtures\Codes;

use Illuminate\Queue\SyncQueue;

/**
 * A queue for tests that builds a job's payload exactly as every Laravel queue
 * does before it stores one, and hands it back instead of running the job, so
 * a test can read what a queued message would leave in the queue's storage.
 *
 * @author      Ben Carey <bdmc@sinemacula.co.uk>
 * @copyright   2026 Sine Macula Limited
 *
 * @internal
 */
final class PayloadRecordingQueue extends SyncQueue
{
    /**
     * The payload a queue would store for the job.
     *
     * @param  object  $job
     * @return string
     */
    public function payloadFor(object $job): string
    {
        return $this->createPayload($job, 'default');
    }
}
