import datetime

class ScannerRunner:
    """Run AWS resource scanners across all specified regions"""
    
    def __init__(self, config=None, regions=None, db_manager=None, scan_id=None):
        """Initialize scanner runner with configuration"""
        self.config = config or {}
        self.provided_regions = regions
        self.account_id = self._get_account_id()
        self.scanner_classes = self._load_scanner_classes()
        self.finding_classes = self._load_finding_classes()
        
        # Store db_manager and scan_id
        self.db_manager = db_manager
        self.scan_id = scan_id
        
        if self.db_manager is None:
            logger.warning("DB Manager not initialized. Resources will not be stored.")
        
        if self.scan_id is None:
            self.scan_id = f"scan_{int(datetime.datetime.now().timestamp())}"
            logger.info(f"Generated scan ID: {self.scan_id}")

def run_scanners(self, region):
    """Run all scanners for a specific region"""
    logger.info(f"Processing region: {region}")
    
    # Create AWS client for this region
    aws_client = self.create_aws_client(region)
    logger.info(f"AWS client initialized for account {self.account_id} in region {region}")
    
    # Run each scanner
    for scanner_class in self.scanner_classes:
        try:
            # Create scanner instance with db_manager and scan_id
            scanner = scanner_class(
                aws_client, 
                self.account_id, 
                region, 
                db_manager=self.db_manager,  # Pass db_manager
                scan_id=self.scan_id         # Pass scan_id
            )
            
            # Log which scanner we're running
            logger.info(f"Running {scanner_class.__name__} in account {self.account_id} region {region}")
            
            # Execute the scanner
            scanner.execute()
        except Exception as e:
            logger.error(f"Error running {scanner_class.__name__}: {str(e)}") 