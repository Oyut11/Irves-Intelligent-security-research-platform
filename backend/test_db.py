import asyncio
from database.connection import get_db
from database.crud import get_scans_by_project, get_findings_by_scan

async def main():
    async with get_db() as db:
        # get any project
        from database.models import Project, Scan, Finding
        from sqlalchemy import select
        result = await db.execute(select(Project).order_by(Project.created_at.desc()).limit(1))
        project = result.scalar_one_or_none()
        if not project:
            print("No project found")
            return
        scans = await get_scans_by_project(db, project.id)
        if not scans:
            print("No scans found for project")
            return
        latest_scan = scans[0]
        
        findings = await get_findings_by_scan(db, latest_scan.id, limit=5000)
        criticals = [f.title for f in findings if (f.severity.value if hasattr(f.severity, 'value') else f.severity) == 'critical']
        print(f"Total findings: {len(findings)}")
        print(f"Critical findings: {len(criticals)}")
        print("Critical titles:", criticals)

asyncio.run(main())
