#include <wolff/Context.h>


namespace wolff
{
    namespace
    {
        OodleDllLoader& DefaultLoader()
        {
            // never destroyed: containers may still decode on a worker while the process ends
            static OodleDllLoader* L = new OodleDllLoader();
            return *L;
        }

        Context& Current()
        {
            static Context C{ nullptr, &DefaultLoader() };
            return C;
        }
    }

    const Context& DefaultContext()
    {
        return Current();
    }

    void SetDefaultContext(const Context& C)
    {
        Current() = C;
        if (Current().Oodle == nullptr) Current().Oodle = &DefaultLoader();
    }
}
