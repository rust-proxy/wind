//! Task management utilities

use std::time::Duration;
use tokio::time;

/// Error indicating a task timed out
#[derive(Debug, thiserror::Error)]
#[error("Task timed out")]
pub struct TimeoutError;

/// Run a future with a timeout
pub async fn with_timeout<T, F>(timeout: Duration, future: F) -> Result<T, TimeoutError>
where
    F: std::future::Future<Output = T>,
{
    match time::timeout(timeout, future).await {
        Ok(result) => Ok(result),
        Err(_) => Err(TimeoutError),
    }
}

/// Run a future with retries
pub async fn with_retries<T, E, F, Fut>(
    max_retries: u32,
    initial_delay: Duration,
    backoff_factor: f64,
    mut operation: F,
) -> Result<T, E>
where
    F: FnMut() -> Fut,
    Fut: std::future::Future<Output = Result<T, E>>,
    E: std::fmt::Debug,
{
    let mut delay = initial_delay;
    
    for attempt in 0..=max_retries {
        match operation().await {
            Ok(result) => return Ok(result),
            Err(e) => {
                if attempt == max_retries {
                    return Err(e);
                }
                
                // Wait before retrying
                time::sleep(delay).await;
                
                // Increase delay for next retry
                delay = Duration::from_secs_f64(delay.as_secs_f64() * backoff_factor);
            }
        }
    }
    
    unreachable!()
}