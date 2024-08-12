<?php

class Container
{
    private $services = [];
    private $instances = [];

    public function set($key, $callable)
    {
        $this->services[$key] = $callable;
    }

    public function get($key)
    {
        if (!isset($this->instances[$key])) {
            if (isset($this->services[$key])) {
                $this->instances[$key] = $this->services[$key]($this);
            } else {
                throw new Exception("Service {$key} not found.");
            }
        }
        return $this->instances[$key];
    }
}
?>
