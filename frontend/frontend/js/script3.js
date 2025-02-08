document.addEventListener("DOMContentLoaded", function () {
    // Fetch data from /data endpoint
    fetch("/data")
      .then((response) => response.json()) // Convert response to JSON
      .then((data) => {
            // Initialize an empty object to hold threat counts
            const threatCounts = {};

            // Loop through each object in the data and extract potential_threats
            for (let key in data) {
                const threats = data[key].static.strings_analysis.potential_threats;
                if (threats) {
                    // Convert threats to lowercase, split by commas, and trim spaces
                    const threatArray = threats.split(",").map(threat => threat.trim().toLowerCase());
                    
                    threatArray.forEach(threat => {
                        if (threatCounts[threat]) {
                            threatCounts[threat] += 1;
                        } else {
                            threatCounts[threat] = 1;
                        }
                    });
                }
            }
            

            // Prepare data for the chart
            const threatLabels = Object.keys(threatCounts);
            const threatData = Object.values(threatCounts);

            // Chart.js configuration with filled area below the line
            const chartData = {
                labels: threatLabels,
                datasets: [{
                    label: 'Threat Frequency',
                    data: threatData,
                    borderColor: 'rgba(75, 192, 192, 1)',
                    backgroundColor: 'rgba(75, 192, 192, 0.2)',
                    fill: true
                }]
            };

            const config = {
                type: 'line',
                data: chartData,
                options: {
                    responsive: true,
                    scales: {
                        x: {
                            title: {
                                display: true,
                                text: 'Known Threats'
                            }
                        },
                        y: {
                            title: {
                                display: true,
                                text: 'Count'
                            },
                            beginAtZero: true
                        }
                    }
                }
            };

            // Create the chart
            const ctx = document.getElementById('threatChart').getContext('2d');
            const threatChart = new Chart(ctx, config);

        })
        .catch((error) => {
          console.error("Error fetching data:", error);
        });
    });