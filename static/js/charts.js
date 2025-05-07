/**
 * Creates and initializes a pie chart for vulnerability summary
 * @param {string} elementId - The ID of the canvas element
 * @param {Array} data - The vulnerability count data [critical, high, medium, low, info]
 */
function initVulnerabilitySummaryChart(elementId, data) {
    const ctx = document.getElementById(elementId).getContext('2d');
    new Chart(ctx, {
        type: 'pie',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                data: data,
                backgroundColor: [
                    '#dc3545', // danger (critical)
                    '#ffc107', // warning (high)
                    '#0d6efd', // primary (medium)
                    '#0dcaf0', // info (low)
                    '#6c757d'  // secondary (info)
                ],
                borderWidth: 1
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#dee2e6'
                    }
                }
            }
        }
    });
}

/**
 * Creates and initializes a line chart for vulnerability trends
 * @param {string} elementId - The ID of the canvas element
 */
function initVulnerabilityTrendsChart(elementId) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    // In a real application, this data would come from the server
    // This is sample data for visualization purposes
    const dates = getLastNDays(7);
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [
                {
                    label: 'Critical',
                    data: [2, 1, 3, 0, 2, 1, 0],
                    borderColor: '#dc3545',
                    backgroundColor: 'rgba(220, 53, 69, 0.1)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'High',
                    data: [5, 4, 6, 3, 7, 5, 4],
                    borderColor: '#ffc107',
                    backgroundColor: 'rgba(255, 193, 7, 0.1)',
                    tension: 0.3,
                    fill: true
                },
                {
                    label: 'Medium',
                    data: [8, 7, 9, 11, 8, 10, 9],
                    borderColor: '#0d6efd',
                    backgroundColor: 'rgba(13, 110, 253, 0.1)',
                    tension: 0.3,
                    fill: true
                }
            ]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#dee2e6'
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#dee2e6'
                    }
                }
            },
            plugins: {
                legend: {
                    position: 'bottom',
                    labels: {
                        color: '#dee2e6'
                    }
                }
            }
        }
    });
}

/**
 * Creates and initializes a horizontal bar chart for common security issues
 * @param {string} elementId - The ID of the canvas element
 */
function initSecurityIssuesChart(elementId) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    // In a real application, this data would come from the server
    // This is sample data for visualization purposes
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: [
                'Missing Security Headers',
                'SSL Certificate Issues',
                'Exposed Sensitive Info',
                'Open Ports',
                'CORS Misconfigurations'
            ],
            datasets: [{
                label: 'Occurrence Count',
                data: [18, 14, 12, 9, 7],
                backgroundColor: [
                    'rgba(13, 110, 253, 0.7)',
                    'rgba(13, 110, 253, 0.7)',
                    'rgba(13, 110, 253, 0.7)',
                    'rgba(13, 110, 253, 0.7)',
                    'rgba(13, 110, 253, 0.7)'
                ],
                borderColor: [
                    'rgba(13, 110, 253, 1)',
                    'rgba(13, 110, 253, 1)',
                    'rgba(13, 110, 253, 1)',
                    'rgba(13, 110, 253, 1)',
                    'rgba(13, 110, 253, 1)'
                ],
                borderWidth: 1
            }]
        },
        options: {
            indexAxis: 'y',
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#dee2e6'
                    }
                },
                y: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#dee2e6'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Creates and initializes a line chart for scan history
 * @param {string} elementId - The ID of the canvas element
 */
function initScanHistoryChart(elementId) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    // In a real application, this data would come from the server
    // This is sample data for visualization purposes
    const dates = getLastNDays(12);
    
    new Chart(ctx, {
        type: 'line',
        data: {
            labels: dates,
            datasets: [{
                label: 'Number of Scans',
                data: [3, 5, 2, 4, 6, 4, 7, 5, 3, 8, 6, 4],
                backgroundColor: 'rgba(13, 202, 240, 0.2)',
                borderColor: 'rgba(13, 202, 240, 1)',
                borderWidth: 2,
                tension: 0.4,
                fill: true
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#dee2e6'
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#dee2e6',
                        stepSize: 1
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Creates and initializes a bar chart for vulnerability distribution
 * @param {string} elementId - The ID of the canvas element
 */
function initVulnerabilityDistributionChart(elementId) {
    const ctx = document.getElementById(elementId).getContext('2d');
    
    // In a real application, this data would come from the server
    // This is sample data for visualization purposes
    new Chart(ctx, {
        type: 'bar',
        data: {
            labels: ['Critical', 'High', 'Medium', 'Low', 'Info'],
            datasets: [{
                label: 'Count',
                data: [15, 42, 67, 89, 123],
                backgroundColor: [
                    '#dc3545', // danger (critical)
                    '#ffc107', // warning (high)
                    '#0d6efd', // primary (medium)
                    '#0dcaf0', // info (low)
                    '#6c757d'  // secondary (info)
                ],
                borderWidth: 0
            }]
        },
        options: {
            responsive: true,
            maintainAspectRatio: false,
            scales: {
                x: {
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#dee2e6'
                    }
                },
                y: {
                    beginAtZero: true,
                    grid: {
                        color: 'rgba(255, 255, 255, 0.1)'
                    },
                    ticks: {
                        color: '#dee2e6'
                    }
                }
            },
            plugins: {
                legend: {
                    display: false
                }
            }
        }
    });
}

/**
 * Helper function to get an array of the last N days formatted as strings
 * @param {number} n - Number of days to include
 * @returns {Array} Array of formatted date strings
 */
function getLastNDays(n) {
    const result = [];
    for (let i = n - 1; i >= 0; i--) {
        const d = new Date();
        d.setDate(d.getDate() - i);
        result.push(d.toLocaleDateString('en-US', { month: 'short', day: 'numeric' }));
    }
    return result;
}
