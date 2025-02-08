document.addEventListener("DOMContentLoaded", function () {
    // Fetch data from /data endpoint
    fetch("/data")
      .then((response) => response.json()) // Convert response to JSON
      .then((rawData) => {
        const malwareCounts = {};
        
        for (const key in rawData) {
          const malwareType =
            rawData[key].static.possible_malware_type;
          if (malwareType) {
            malwareCounts[malwareType] =
              (malwareCounts[malwareType] || 0) + 1;
          }
          console.log("Fetched data:", rawData);
        }

        // Step 2: Prepare data for the chart
        const labels = Object.keys(malwareCounts);
        const data = Object.values(malwareCounts);

        // Step 3: Create the pie chart
        const ctx = document
          .getElementById("malwareChart")
          .getContext("2d");
        new Chart(ctx, {
          type: "pie",
          data: {
            labels: labels, // Malware types
            datasets: [
              {
                label: "Malware Type Distribution",
                data: data, // Count of each malware type
                backgroundColor: [
                  "rgba(255, 99, 132, 0.6)",
                  "rgba(54, 162, 235, 0.6)",
                  "rgba(255, 206, 86, 0.6)",
                  "rgba(75, 192, 192, 0.6)",
                  "rgba(153, 102, 255, 0.6)",
                  "rgba(255, 159, 64, 0.6)",
                ],
                borderWidth: 1,
              },
            ],
          },
          options: {
            responsive: true,
            plugins: {
              legend: {
                position: "top",
              },
              title: {
                display: true,
                text: "Malware Type Distribution",
              },
            },
          },
        });
      })
      .catch((error) => {
        console.error("Error fetching data:", error);
      });
  });