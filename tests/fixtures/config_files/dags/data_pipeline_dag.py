"""
Real-world Airflow DAG for data pipeline orchestration.
Based on typical ETL workflow in production data engineering.
"""

from datetime import datetime, timedelta
from airflow import DAG
from airflow.operators.python import PythonOperator
from airflow.operators.bash import BashOperator
from airflow.sensors.external_task import ExternalTaskSensor

# Default arguments for the DAG
default_args = {
    'owner': 'data-engineering',
    'depends_on_past': False,
    'start_date': datetime(2024, 1, 1),
    'email': ['alerts@company.com'],
    'email_on_failure': True,
    'email_on_retry': False,
    'retries': 3,
    'retry_delay': timedelta(minutes=5),
}

# DAG definition
dag = DAG(
    'daily_data_pipeline',
    default_args=default_args,
    description='Daily ETL pipeline for processing customer data',
    schedule_interval='0 2 * * *',  # Run at 2 AM daily
    catchup=False,
    tags=['etl', 'production', 'daily'],
)

# Task 1: Extract data from source systems
extract_customer_data = PythonOperator(
    task_id='extract_customer_data',
    python_callable=extract_customers,
    dag=dag,
)

extract_orders_data = PythonOperator(
    task_id='extract_orders_data',
    python_callable=extract_orders,
    dag=dag,
)

extract_product_catalog = PythonOperator(
    task_id='extract_product_catalog',
    python_callable=extract_products,
    dag=dag,
)

# Task 2: Data quality checks
validate_customer_data = PythonOperator(
    task_id='validate_customer_data',
    python_callable=validate_customers,
    dag=dag,
)

validate_orders_data = PythonOperator(
    task_id='validate_orders_data',
    python_callable=validate_orders,
    dag=dag,
)

# Task 3: Transform and enrich data
transform_customer_data = PythonOperator(
    task_id='transform_customer_data',
    python_callable=transform_customers,
    dag=dag,
)

calculate_customer_lifetime_value = PythonOperator(
    task_id='calculate_clv',
    python_callable=calculate_clv,
    dag=dag,
)

enrich_order_data = PythonOperator(
    task_id='enrich_orders',
    python_callable=enrich_orders,
    dag=dag,
)

# Task 4: Load to data warehouse
load_to_warehouse = PythonOperator(
    task_id='load_to_warehouse',
    python_callable=load_data_warehouse,
    dag=dag,
)

# Task 5: Update materialized views
refresh_analytics_views = BashOperator(
    task_id='refresh_analytics_views',
    bash_command='python -m analytics.refresh_views',
    dag=dag,
)

# Task 6: Generate reports
generate_daily_report = PythonOperator(
    task_id='generate_daily_report',
    python_callable=generate_report,
    dag=dag,
)

# Task 7: Send notifications
send_success_notification = PythonOperator(
    task_id='send_notification',
    python_callable=send_notification,
    dag=dag,
)

# Task 8: Cleanup temporary files
cleanup_temp_files = PythonOperator(
    task_id='cleanup_temp_files',
    python_callable=cleanup_files,
    dag=dag,
)

# Define task dependencies
# Extract phase (parallel)
extract_customer_data >> validate_customer_data
extract_orders_data >> validate_orders_data
extract_product_catalog

# Transform phase (sequential with validation)
validate_customer_data >> transform_customer_data
transform_customer_data >> calculate_customer_lifetime_value
validate_orders_data >> enrich_order_data

# Load phase (wait for all transforms)
[calculate_customer_lifetime_value, enrich_order_data, extract_product_catalog] >> load_to_warehouse

# Post-load operations
load_to_warehouse >> refresh_analytics_views
refresh_analytics_views >> generate_daily_report
generate_daily_report >> send_success_notification
send_success_notification >> cleanup_temp_files


# Additional DAG for real-time processing
realtime_dag = DAG(
    'realtime_event_processing',
    default_args=default_args,
    description='Real-time event stream processing',
    schedule_interval=None,  # Triggered externally
    tags=['realtime', 'streaming'],
)

# Real-time tasks
process_user_events = PythonOperator(
    task_id='process_user_events',
    python_callable=process_events,
    dag=realtime_dag,
)

update_user_segments = PythonOperator(
    task_id='update_segments',
    python_callable=update_segments,
    dag=realtime_dag,
)

trigger_personalization = PythonOperator(
    task_id='trigger_personalization',
    python_callable=trigger_personalization_engine,
    dag=realtime_dag,
)

# Real-time task dependencies
process_user_events >> update_user_segments >> trigger_personalization
