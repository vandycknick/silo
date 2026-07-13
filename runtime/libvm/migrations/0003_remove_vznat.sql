UPDATE network_definitions
SET driver_preference = jsonb('"netd"')
WHERE json(driver_preference) = '"vznat"';

DELETE FROM network_instances
WHERE driver = 'vznat';
