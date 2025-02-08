fetch('/data')
      .then(response => response.json())
      .then(data => {
        const tableBody = document.getElementById('table-body');

        // Loop through each file
        Object.keys(data).forEach(filename => {
          const file = data[filename];
          const fileType = file.static.static_analysis.file_type;
          const maliciousnessScore = "Removed";
          const threatLevel = file.static.static_analysis.maliciousness_score > 7.5 ? 'High' : 'Medium';
          const malwareType = file.static.possible_malware_type;
          const justification = file.static.strings_analysis.justification;
          const filepath = file.static.static_analysis.filepath;	
          const timestamp = file.static.static_analysis.timestamp;
		
          const staticAnalysis = file.static.static_analysis.rating_justification;
          const stringAnalysis = file.static.strings_analysis.justification;
          
          let dnsAnalysis = 'No DNS activity observed.';
          let tcpAnalysis = 'No TCP activity observed.';
          console.log(file)
          if('dynamic' in file){
          if ('dns_analysis' in file.dynamic) {
              dnsAnalysis = file.dynamic.dns_analysis.justification || dnsAnalysis;
          }

          if ('tcp_analysis' in file.dynamic) {
              tcpAnalysis = file.dynamic.tcp_analysis.justification || tcpAnalysis;
          }
          }
          // Create the main row
          const mainRow = document.createElement('tr');
          mainRow.innerHTML = `
            <td class="m-b-0 font-16">${filename}</td>
            <td>${fileType}</td>
            <td>${maliciousnessScore}</td>
            <td><label class="label label-danger">${threatLevel}></label><h5>${threatLevel}</h5></td>
            <td>${malwareType}</td>
            <td>${filepath}</td>
            <td>${timestamp}</td>
            <td>Expand for more details.</td>
            <td class="expand-icon">&#9660;</td>
          `;

          // Create the hidden details row
          const detailsRow = document.createElement('tr');
          detailsRow.classList.add('hidden-details');
          detailsRow.innerHTML = `
            <td colspan="7">
              <div class="details-section">
                <strong>Static Analysis:</strong>
                <p>${staticAnalysis}</p>
              </div>
              <div class="details-section">
                <strong>String Analysis:</strong>
                <p>${stringAnalysis}</p>
              </div>
              <div class="details-section">
                <strong>DNS Analysis:</strong>
                <p>${dnsAnalysis}</p>
              </div>
              <div class="details-section">
                <strong>TCP Analysis:</strong>
                <p>${tcpAnalysis}</p>
              </div>
            </td>
          `;

          // Add a click event to the expand icon
          mainRow.querySelector('.expand-icon').addEventListener('click', () => {
            if (detailsRow.style.display === 'table-row') {
              detailsRow.style.display = 'none';
              mainRow.querySelector('.expand-icon').innerHTML = '&#9660;'; // Down arrow
            } else {
              detailsRow.style.display = 'table-row';
              mainRow.querySelector('.expand-icon').innerHTML = '&#9650;'; // Up arrow
            }
          });

          // Append both rows to the table
          tableBody.appendChild(mainRow);
          tableBody.appendChild(detailsRow);
        });
      })
      .catch(error => console.error('Error fetching data:', error));