#pragma once
#include "Pch.h"

namespace Util {
	
	template<class _Ty1, class _Ty2 = _Ty1>
	auto alignTo(_Ty1 number, _Ty2 alignment) {
		return (number + alignment - 1) / alignment * alignment;
	}

}

