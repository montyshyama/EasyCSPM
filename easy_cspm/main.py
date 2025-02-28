def run_cspm_scan(config=None, regions=None, output_file=None):
    """Run a CSPM scan with the given configuration"""
    try:
        # Initialize database manager
        db_manager = DBManager()
        
        # Create a scan ID
        scan_id = f"scan_{int(datetime.datetime.now().timestamp())}"
        
        # Initialize the scanner runner with db_manager and scan_id
        scanner_runner = ScannerRunner(
            config=config, 
            regions=regions,
            db_manager=db_manager,  # Pass db_manager here
            scan_id=scan_id         # Pass scan_id here
        )
        
        # Run the scan
        scanner_runner.run()
        
        # Export findings if output file provided
        if output_file:
            export_findings_to_csv(db_manager, scan_id, output_file)
        
        return True
    except Exception as e:
        logger.error(f"Error running CSPM scan: {str(e)}")
        return False 