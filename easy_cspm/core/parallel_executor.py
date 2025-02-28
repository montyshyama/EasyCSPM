import concurrent.futures
import time
from tqdm import tqdm
from ..core.logging_config import logger
from ..core.exceptions import ParallelExecutionError

class ParallelExecutor:
    """Handles parallel execution of tasks with progress tracking"""
    
    def __init__(self, max_workers=20, timeout=None, description="Processing"):
        """Initialize parallel executor with max workers and timeout"""
        self.max_workers = max_workers
        self.timeout = timeout
        self.description = description
        logger.info(f"Initialized parallel executor with {max_workers} workers")
    
    def execute(self, tasks, show_progress=True):
        """
        Execute tasks in parallel
        
        Args:
            tasks: List of (function, args, kwargs) tuples to execute
            show_progress: Whether to show a progress bar
            
        Returns:
            List of results in the same order as tasks
        """
        start_time = time.time()
        results = []
        errors = []
        
        with concurrent.futures.ThreadPoolExecutor(max_workers=self.max_workers) as executor:
            # Submit all tasks
            future_to_task = {
                executor.submit(func, *args, **kwargs): (i, func.__name__)
                for i, (func, args, kwargs) in enumerate(tasks)
            }
            
            # Setup progress bar if requested
            if show_progress:
                pbar = tqdm(total=len(tasks), desc=self.description)
            
            # Process completed tasks as they finish
            for future in concurrent.futures.as_completed(future_to_task):
                task_idx, func_name = future_to_task[future]
                
                try:
                    result = future.result(timeout=self.timeout)
                    results.append((task_idx, result))
                    logger.debug(f"Task {func_name} completed successfully")
                except Exception as e:
                    errors.append((task_idx, str(e)))
                    logger.error(f"Task {func_name} failed: {str(e)}")
                
                if show_progress:
                    pbar.update(1)
            
            if show_progress:
                pbar.close()
        
        # Sort results by original task index
        results.sort(key=lambda x: x[0])
        errors.sort(key=lambda x: x[0])
        
        # Log summary
        elapsed = time.time() - start_time
        success_count = len(results)
        error_count = len(errors)
        total_count = len(tasks)
        
        logger.info(f"Completed {total_count} tasks in {elapsed:.2f} seconds. "
                   f"Success: {success_count}, Errors: {error_count}")
        
        if errors:
            for idx, error_msg in errors[:5]:  # Log first 5 errors
                logger.error(f"Task {idx} error: {error_msg}")
            
            if len(errors) > 5:
                logger.error(f"... and {len(errors) - 5} more errors")
            
            if error_count == total_count:
                raise ParallelExecutionError(f"All {total_count} tasks failed")
        
        # Return only the results, without the task indices
        return [result for _, result in results] 