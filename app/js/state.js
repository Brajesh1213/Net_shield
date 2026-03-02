/**
 * state.js — Application-wide state object
 * Single source of truth shared across all JS modules.
 */

export const state = {
    engineRunning:      false,
    isAdmin:            false,
    subscriptionStatus: '',     // 'active' | 'beta' | 'expired' | ''
    threatCount:        0,
    blockCount:         0,
    fileThreatCount:    0,
    procThreatCount:    0,
    scanCount:          0,
    alertCount:         0,
    unreadAlerts:       0,
    userEmail:          '',
    userToken:          '',
    timelineData:       Array(60).fill(0),
    timelineTick:       0,
    currentFilter:      'all',
    allAlerts:          [],   // { el, type } for filter support
};
