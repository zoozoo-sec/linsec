document.addEventListener('DOMContentLoaded', () => {
    // Check if a state is saved in localStorage, otherwise set to "ON" by default
    const savedState = localStorage.getItem('serviceState') || 'ON'; // Default is 'ON' if nothing is saved
  
    const serviceToggle = document.getElementById('serviceToggle');
    const serviceStatus = document.getElementById('serviceStatus');
    
    // Set the toggle state
    serviceToggle.checked = savedState === 'ON'; // Set toggle state based on savedState
    serviceStatus.textContent = `Service: ${savedState}`; // Display the correct state
  
    // Send the default state to the backend on page load if necessary
    fetch(`/service-toggle?state=${savedState}`, {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json',
      },
    })
    .then(response => response.json())
    .then(data => {
      console.log('Server Response:', data);
    })
    .catch(error => {
      console.error('Error:', error);
    });
    
    // Add event listener for state changes
    serviceToggle.addEventListener('change', function() {
      const status = this.checked ? 'ON' : 'OFF';
      serviceStatus.textContent = `Service: ${status}`;
      
      // Save the state to localStorage
      localStorage.setItem('serviceState', status);
      
      // Send the state change to the backend
      fetch(`/service-toggle?state=${status}`, {
        method: 'GET',
        headers: {
          'Content-Type': 'application/json',
        },
      })
      .then(response => response.json())
      .then(data => {
        console.log('Server Response:', data);
      })
      .catch(error => {
        console.error('Error:', error);
      });
    });
  });
  