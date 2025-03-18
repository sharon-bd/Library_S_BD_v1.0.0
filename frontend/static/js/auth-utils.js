// Common authentication utilities for all user pages
function getCookie(name) {
    const value = `; ${document.cookie}`;
    const parts = value.split(`; ${name}=`);
    if (parts.length === 2) return parts.pop().split(";").shift();
    return null;
  }
  
  // Authentication verification function with special case handling
  function checkAuthentication() {
    console.log("Checking authentication...");
    
    // Special case for recommended_books.html - ALWAYS return true for this page
    const currentPage = window.location.pathname;
    if (currentPage.includes('recommended_books.html')) {
      console.log("Special authentication bypass for recommended books page");
      return true;
    }
    
    const cookieToken = getCookie("access_token");
    const localToken = localStorage.getItem("customer_token");
    
    // Check URL parameters to see if we're coming directly from login
    const urlParams = new URLSearchParams(window.location.search);
    const isFromLogin = urlParams.has("ts"); // The timestamp parameter from login redirect
    
    // Add a special parameter to force authentication for testing
    const forceAuth = urlParams.has("force_auth");
    
    if (forceAuth) {
      console.log("Forced authentication via URL parameter");
      return true;
    }
    
    if (!cookieToken && !localToken && !isFromLogin) {
      console.warn("No authentication token found");
      window.location.href = "/frontend/html/homepage.html";
      return false;
    }
    console.log("Authentication successful");
    return true;
  }
  
  // Used to get customer data from API
  function fetchCustomerData() {
    // Set Authorization header for API requests if localStorage token exists
    const headers = { "Content-Type": "application/json" };
    const localToken = localStorage.getItem("customer_token");
    if (localToken) {
      headers["Authorization"] = `Bearer ${localToken}`;
    }
    
    return fetch("/api/customer_data", {
      method: "GET",
      headers: headers,
      credentials: "include" // This ensures cookies are sent with the request
    })
    .then(response => {
      if (!response.ok) {
        throw new Error(`Server returned status: ${response.status}`);
      }
      return response.json();
    });
  }
  
  // Make the logout function more robust
  function logout() {
    console.log("Performing logout operations...");
    
    // Clear localStorage tokens
    localStorage.removeItem("customer_token");
    localStorage.removeItem("last_page");
    
    // Clear all potential auth cookies by setting expiration in the past
    document.cookie = "access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    document.cookie = "developer_access=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/;";
    
    // Force path-specific cookie cleanup (in case path was specified during cookie creation)
    document.cookie = "access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/frontend/;";
    document.cookie = "access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/frontend/user_pages/;";
    document.cookie = "access_token=; expires=Thu, 01 Jan 1970 00:00:00 UTC; path=/api/;";
    
    console.log("Logout complete, redirecting to homepage");
    
    // Add a timestamp to prevent caching when redirecting
    window.location.href = "/frontend/html/homepage.html?logout=" + Date.now();
  }

  // Removes cookies from all possible storage paths
  // Add this to auth-utils.js
  function navigateTo(page) {
    // Preserve authentication by adding timestamp to prevent caching issues
    window.location.href = page + "?ts=" + Date.now();
  }

  // Includes dynamic parameter to prevent page caching
  // Add this to auth-utils.js
  function displaySessionExpiration() {
    fetch('/api/user_session', {
      method: 'GET',
      headers: {
        'Content-Type': 'application/json'
      },
      credentials: 'include'
    })
    .then(response => response.json())
    .then(data => {
      if (data.success && data.session) {
        // Create or update session info display
        let sessionInfoElement = document.getElementById('session-expiration-info');
        if (!sessionInfoElement) {
          sessionInfoElement = document.createElement('div');
          sessionInfoElement.id = 'session-expiration-info';
          sessionInfoElement.className = 'session-info';
          sessionInfoElement.style.backgroundColor = '#fff3cd';
          sessionInfoElement.style.color = '#856404';
          sessionInfoElement.style.padding = '0.75rem';
          sessionInfoElement.style.margin = '1rem 0';
          sessionInfoElement.style.borderRadius = '0.25rem';
          sessionInfoElement.style.textAlign = 'center';
          sessionInfoElement.style.fontWeight = 'bold';
          
          // Find a good place to add this element
          const container = document.querySelector('.container') || document.body;
          container.prepend(sessionInfoElement);
        }
        
        // Update the content
        const role = data.session.role.charAt(0).toUpperCase() + data.session.role.slice(1);
        sessionInfoElement.textContent = `${role} session ${data.session.expires}`;
      }
    })
    .catch(err => console.error('Error fetching session info:', err));
  }
  
  // Call this when pages load
  document.addEventListener('DOMContentLoaded', function() {
    // Delay slightly to ensure all cookies are loaded
    setTimeout(displaySessionExpiration, 500);
  });

// Formats and displays user role and session expiration

// Parameter check for bypassing authentication requirements

// Function to display session expiration information

// Includes timestamp parameter for cache control

// Event listener for initializing session information display

// Selects appropriate container for session information display