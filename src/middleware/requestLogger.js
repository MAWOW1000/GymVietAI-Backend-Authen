const requestLogger = (req, res, next) => {
    const start = Date.now();
    
    // Log request details
    console.log('\n=== Auth Service Request Log ===');
    console.log(`Time: ${new Date().toISOString()}`);
    console.log(`Method: ${req.method}`);
    console.log(`URL: ${req.originalUrl}`);
    console.log('Headers:', req.headers);
    console.log('Body:', req.body);

    // Store original send
    const originalSend = res.send;

    // Override send
    res.send = function (data) {
        // Log response data
        console.log('\n=== Auth Service Response Log ===');
        console.log(`Time: ${new Date().toISOString()}`);
        console.log(`Status: ${res.statusCode}`);
        console.log('Response:', data);
        const duration = Date.now() - start;
        console.log(`Duration: ${duration}ms`);
        console.log('========================\n');

        // Call original send
        originalSend.apply(res, arguments);
    };

    next();
};

module.exports = requestLogger;
