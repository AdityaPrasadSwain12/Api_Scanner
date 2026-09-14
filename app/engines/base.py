from abc import ABC, abstractmethod

from app.domain import EngineResult, ScanContext


class ScannerEngine(ABC):
    name: str

    @abstractmethod
    async def validate(self, context: ScanContext) -> tuple[bool, str | None]: ...

    async def prepare(self, context: ScanContext) -> None:
        return None

    @abstractmethod
    async def execute(self, context: ScanContext) -> EngineResult: ...

    async def collect_results(self, result: EngineResult) -> EngineResult:
        return result

    async def normalize(self, result: EngineResult) -> EngineResult:
        return result

    async def cleanup(self, context: ScanContext) -> None:
        return None

    async def run(self, context: ScanContext) -> EngineResult:
        valid, reason = await self.validate(context)
        if not valid:
            return EngineResult(engine=self.name, status="SKIPPED", reason=reason)
        try:
            await self.prepare(context)
            result = await self.execute(context)
            return await self.normalize(await self.collect_results(result))
        finally:
            await self.cleanup(context)
