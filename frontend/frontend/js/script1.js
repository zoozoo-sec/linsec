fetch("/data")
    .then(response => response.json()) // Convert response to JSON
    .then(data => {
        const antivirusEngines = new Set();
        const results = {
            malicious: {},
            timeout: {}
        };

        Object.values(data).forEach(file => {
            const detections = file.static.static_analysis.virustotal_detections;
            Object.entries(detections).forEach(([engine, result]) => {
                antivirusEngines.add(engine);
                if (!results[result][engine]) results[result][engine] = 0;
                results[result][engine]++;
            });
        });

        // Prepare chart data
        const labels = Array.from(antivirusEngines);
        const maliciousData = labels.map(engine => results.malicious[engine] || 0);
        const timeoutData = labels.map(engine => results.timeout[engine] || 0);

        const chartData = {
            labels,
            datasets: [
                {
                    label: "Malicious",
                    data: maliciousData,
                    backgroundColor: "rgba(255, 99, 132, 0.8)"
                },
                {
                    label: "Timeout",
                    data: timeoutData,
                    backgroundColor: "rgba(54, 162, 235, 0.8)"
                }
            ]
        };

        // Configure the chart
        const config = {
            type: "bar",
            data: chartData,
            options: {
                responsive: true,
                plugins: {
                    legend: {
                        position: "top"
                    },
                    title: {
                        display: true,
                        text: "Antivirus Detection Results by Engine"
                    }
                },
                scales: {
                    x: {
                        stacked: true
                    },
                    y: {
                        stacked: true,
                        ticks: {
                            beginAtZero: true, // Start the y-axis at 0
                            stepSize: 1, // Ensure ticks increment by 1
                            callback: function (value) {
                                // Only show whole numbers on the y-axis
                                if (Number.isInteger(value)) {
                                    return value;
                                }
                            }
                        }
                    }
                }
            }
        };

        // Render the chart
        const ctx = document.getElementById("antivirusChart").getContext("2d");
        new Chart(ctx, config);
    })
    .catch(error => {
        console.error("Error fetching data:", error);
    });



