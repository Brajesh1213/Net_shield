/**
 * chart.js — Timeline Chart component (Threats page)
 * Line chart showing threats-per-second over the last 60 seconds.
 * Requires Chart.js loaded globally via CDN in index.html.
 */

import { state } from './state.js';

let timelineChart = null;

/**
 * Initialize the Chart.js timeline and start the 1-second tick.
 * Must be called after DOMContentLoaded.
 */
export function initChart() {
    const ctx = document.getElementById('chart-timeline')?.getContext('2d');
    if (!ctx) return;

    Chart.defaults.color = '#94a3b8';

    timelineChart = new Chart(ctx, {
        type: 'line',
        data: {
            labels: Array(60).fill(''),
            datasets: [{
                label: 'Threats/s',
                data: [...state.timelineData],
                borderColor: '#0d9fd8',
                backgroundColor: 'rgba(13,159,216,.10)',
                borderWidth: 2,
                pointRadius: 0,
                tension: 0.4,
                fill: true,
            }],
        },
        options: {
            animation: false,
            responsive: true,
            maintainAspectRatio: false,
            plugins: { legend: { display: false } },
            scales: {
                x: { display: false },
                y: {
                    min: 0,
                    ticks: { stepSize: 1, font: { size: 10 } },
                    grid: { color: 'rgba(148,163,184,.08)' },
                },
            },
        },
    });

    // Advance the chart every second
    setInterval(() => {
        state.timelineData.push(state.timelineTick);
        state.timelineData.shift();
        state.timelineTick = 0;
        if (timelineChart) {
            timelineChart.data.datasets[0].data = [...state.timelineData];
            timelineChart.update('none');
        }
    }, 1000);
}
