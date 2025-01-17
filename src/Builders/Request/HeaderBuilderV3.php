<?php

namespace EbicsApi\Ebics\Builders\Request;

use Closure;

/**
 * Ebics 3.0 Class HeaderBuilder builder for request container.
 *
 * @license http://www.opensource.org/licenses/mit-license.html  MIT License
 * @author Andrew Svirin
 */
final class HeaderBuilderV3 extends HeaderBuilder
{
    public function addStatic(Closure $callback): HeaderBuilder
    {
        $staticBuilder = new StaticBuilderV3($this->cryptService, $this->dom);
        $this->instance->appendChild($staticBuilder->createInstance()->getInstance());

        call_user_func($callback, $staticBuilder);

        return $this;
    }
}
